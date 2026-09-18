package controller

import (
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
)

// The name webshark itself will accept - src/main.go. A capture file it refuses
// is a capture nobody ever sees, so this is the one thing here worth a test.
var websharkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,127}$`)

func TestCaptureFileName(t *testing.T) {
	at := time.Date(2026, 9, 16, 11, 16, 11, 0, time.UTC)

	for _, c := range []struct {
		name            string
		prefix, ns, pod string
		want            string
	}{
		{"plain", "", "demo", "web-75d8d959fb-4tggn", "web-75d8d959fb-4tggn-demo-20260916-111611.pcap"},
		{"prefix", "live-", "demo", "web", "live-web-demo-20260916-111611.pcap"},
		{"unprintable", "", "demo", "we/b:1", "we-b-1-demo-20260916-111611.pcap"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := captureFileName(c.prefix, c.ns, c.pod, at); got != c.want {
				t.Errorf("captureFileName = %q, want %q", got, c.want)
			}
		})
	}

	t.Run("long names still fit", func(t *testing.T) {
		got := captureFileName("", strings.Repeat("n", 63), strings.Repeat("p", 63), at)
		if !websharkName.MatchString(got) {
			t.Errorf("captureFileName = %q, which webshark will not accept", got)
		}
		if !strings.HasSuffix(got, "-20260916-111611.pcap") {
			t.Errorf("captureFileName = %q, truncated the time rather than the pod", got)
		}
	})
}

func TestCapturePodName(t *testing.T) {
	name := CapturePodName("ims", "sip", "ims", "pcscf-0")
	if !strings.HasPrefix(name, "pcap-sip-pcscf-0-") {
		t.Errorf("CapturePodName = %q, which does not say what it is capturing", name)
	}

	// Every capture pod in the cluster is in the operator's one namespace, so
	// the name has to separate captures and targets that only differ somewhere
	// in their namespaces.
	seen := map[string]string{}
	for _, c := range []struct{ captureNS, capture, targetNS, target string }{
		{"ims", "sip", "ims", "pcscf-0"},
		{"ims", "sip", "ims", "pcscf-1"},
		{"ims", "sip", "core", "pcscf-0"},
		{"core", "sip", "ims", "pcscf-0"},
		{"ims", "diameter", "ims", "pcscf-0"},
		{strings.Repeat("n", 63), strings.Repeat("c", 63), strings.Repeat("t", 63), strings.Repeat("p", 63)},
		{strings.Repeat("n", 63), strings.Repeat("c", 63), strings.Repeat("t", 63), strings.Repeat("q", 63)},
	} {
		got := CapturePodName(c.captureNS, c.capture, c.targetNS, c.target)
		if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
			t.Errorf("CapturePodName = %q: %v", got, errs)
		}
		if len(got) > 63 {
			t.Errorf("CapturePodName = %q (%d), too long for a pod name", got, len(got))
		}
		if was, dup := seen[got]; dup {
			t.Errorf("CapturePodName = %q for both %v and %s", got, c, was)
		}
		seen[got] = c.captureNS + "/" + c.capture + " -> " + c.targetNS + "/" + c.target
	}
}

func TestCapturePod(t *testing.T) {
	pc := &websharkv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ims", Name: "sip"},
		Spec: websharkv1alpha1.PacketCaptureSpec{
			Filter:   "udp port 5060",
			Duration: metav1.Duration{Duration: 90 * time.Second},
		},
	}
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ims", Name: "pcscf-0"},
		Spec:       corev1.PodSpec{NodeName: "node-2"},
		Status: corev1.PodStatus{
			PodIP:  "10.1.2.3",
			PodIPs: []corev1.PodIP{{IP: "10.1.2.3"}, {IP: "fd00::3"}},
		},
	}
	pod := capturePod("webshark", "pcap-sip-pcscf-0-abc1234", pc, target, "img", "", "http://webshark:8085/api/file?f=a.pcap")

	// On the target's node and past the scheduler, which is the whole point:
	// anywhere else and it is in the wrong network namespace.
	if pod.Spec.NodeName != "node-2" {
		t.Errorf("nodeName = %q, want node-2", pod.Spec.NodeName)
	}
	if !pod.Spec.HostPID {
		t.Error("without hostPID the target's processes are not visible, so its netns cannot be found")
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy = %q: a finished capture must not be started again", pod.Spec.RestartPolicy)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Error("the capture has no business with the API server and should carry no token")
	}
	if want := int64(90 + captureDeadlineSlack.Seconds()); pod.Spec.ActiveDeadlineSeconds == nil || *pod.Spec.ActiveDeadlineSeconds != want {
		t.Errorf("activeDeadlineSeconds = %v, want %d", pod.Spec.ActiveDeadlineSeconds, want)
	}
	if pod.Labels[LabelTarget] != "pcscf-0" || pod.Labels[LabelCapture] != "sip" {
		t.Errorf("labels = %v, which is not enough to find this pod again by", pod.Labels)
	}

	container := pod.Spec.Containers[0]
	env := map[string]string{}
	for _, e := range container.Env {
		env[e.Name] = e.Value
	}
	// Both families: the namespace is found by whichever address answers, and a
	// cluster can be single-stack in either.
	if env["WS_PODIPS"] != "10.1.2.3 fd00::3" {
		t.Errorf("WS_PODIPS = %q, want both of the pod's addresses", env["WS_PODIPS"])
	}
	if env["WS_FILTER"] != "udp port 5060" || env["WS_DURATION"] != "90" {
		t.Errorf("env = %v", env)
	}

	// The capabilities are the whole security story: setns into another pod's
	// network namespace, and the packet socket once there. Not privileged.
	caps := map[corev1.Capability]bool{}
	for _, c := range container.SecurityContext.Capabilities.Add {
		caps[c] = true
	}
	for _, want := range []corev1.Capability{"NET_RAW", "SYS_ADMIN", "SYS_PTRACE"} {
		if !caps[want] {
			t.Errorf("capabilities = %v, missing %s", container.SecurityContext.Capabilities.Add, want)
		}
	}
	if sc := container.SecurityContext; sc.Privileged != nil && *sc.Privileged {
		t.Error("a capture pod does not need to be privileged, and saying so would be a much larger ask")
	}
	// A capture pod can have them, which is worth keeping true: a tcpdump with
	// no memory limit on a busy node is the operator's problem and not the
	// kubelet's.
	if container.Resources.Requests.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
		t.Errorf("resources = %v, want requests and a memory limit", container.Resources)
	}
}

func TestStopReason(t *testing.T) {
	running := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	pc := &websharkv1alpha1.PacketCapture{}

	if reason := stopReason(pc, running); reason != "" {
		t.Errorf("stopReason = %q for a running pod, want none", reason)
	}
	// A pod on its way out is still worth capturing: deletion is when it says
	// goodbye, and that is usually the packet the capture was started for.
	terminating := running.DeepCopy()
	terminating.DeletionTimestamp = ptrTime(metav1.Now())
	if reason := stopReason(pc, terminating); reason != "" {
		t.Errorf("stopReason = %q for a terminating pod, which is still running", reason)
	}
	if reason := stopReason(pc, nil); reason != "pod gone" {
		t.Errorf("stopReason = %q, want \"pod gone\"", reason)
	}
	if reason := stopReason(pc, &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}); reason != "pod succeeded" {
		t.Errorf("stopReason = %q, want \"pod succeeded\"", reason)
	}
	paused := &websharkv1alpha1.PacketCapture{Spec: websharkv1alpha1.PacketCaptureSpec{Paused: true}}
	if reason := stopReason(paused, running); reason != "paused" {
		t.Errorf("stopReason = %q, want \"paused\" - pausing a capture stops it", reason)
	}
}
