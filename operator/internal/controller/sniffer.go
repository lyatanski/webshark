package controller

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
)

// What a capture pod is labelled with. Its name is derived and so says the same
// thing, but a label is what a list can be asked for: this is how a capture's
// pods are found again after the operator restarts, and how the page knows
// which pod a capture pod is capturing.
const (
	LabelCapture          = "webshark.io/capture"
	LabelCaptureNamespace = "webshark.io/capture-namespace"
	LabelTarget           = "webshark.io/target"
	LabelTargetNamespace  = "webshark.io/target-namespace"
)

// CaptureFinalizer keeps a PacketCapture around long enough to delete the pods
// that are capturing for it: deleting the object is how a capture is asked to
// stop, and a capture that outlived the object that asked for it would be a
// capture nobody could stop at all.
const CaptureFinalizer = "webshark.io/captures"

// captureContainer is the one container in a capture pod.
const captureContainer = "tcpdump"

// captureDeadlineSlack is added to the duration to get the pod's
// activeDeadlineSeconds. The script's own timer is what ends a capture; this is
// only a backstop for an upload that never returns, so it is generous.
const captureDeadlineSlack = 5 * time.Minute

// The whole of a capture, kept here rather than built into one unreadable -c
// string so that `kubectl get pod -o yaml` shows what is running.
//
// tcpdump runs in the target pod's network namespace and curl runs in this one,
// the two joined by a fifo. Only the capture crosses over, which is worth the
// fifo: the upload goes out of this pod's own address instead of the target's,
// and so is not itself in the capture, as it is when the whole thing runs inside
// the pod.
//
// Nothing is written to the node - the fifo is a memory-backed emptyDir and
// holds no data - and nothing here asks the container runtime anything, so
// there is no CRI socket to mount and nothing to know about containerd.
const nodeSnifferScript = `set -eu

# The target's network namespace. hostPID makes every process on the node
# visible; each namespace is looked at once, deduplicated by the inode behind
# /proc/<pid>/ns/net, and the one holding one of the pod's addresses is the
# pod's.
target() {
	seen=
	for proc in /proc/[0-9]*; do
		ns=$(readlink "$proc/ns/net" 2>/dev/null) || continue
		case " $seen " in *" $ns "*) continue ;; esac
		seen="$seen $ns"
		pid=${proc#/proc/}
		addrs=$(nsenter -t "$pid" -n ip -o addr show 2>/dev/null) || continue
		for ip in $WS_PODIPS; do
			case "$addrs" in
			*" inet $ip/"* | *" inet6 $ip/"*) echo "$pid"; return 0 ;;
			esac
		done
	done
	return 1
}

pid=$(target) || {
	echo "webshark: no network namespace on this node holds $WS_PODIPS - the pod went" >&2
	exit 2
}

set -- -i "$WS_IFACE" -U -n -w -
[ "$WS_SNAPLEN" = 0 ] || set -- "$@" -s "$WS_SNAPLEN"
[ "$WS_MAXPACKETS" = 0 ] || set -- "$@" -c "$WS_MAXPACKETS"
[ -z "$WS_FILTER" ] || set -- "$@" "$WS_FILTER"

echo "webshark: tcpdump $* in the netns of pid $pid -> $WS_URL" >&2

mkfifo /tmp/pcap
curl -sS --fail-with-body -X POST -T - "$WS_URL" < /tmp/pcap &
upload=$!
nsenter -t "$pid" -n -F tcpdump "$@" > /tmp/pcap &
capture=$!

# SIGINT ends the capture, from whichever end asks for it: the duration running
# out, or the kubelet's SIGTERM when this pod is deleted. tcpdump flushes what
# it has and closes the fifo, curl finishes the POST, and the file in webshark
# is whole.
trap 'kill -INT "$capture" 2>/dev/null || true' INT TERM
[ "$WS_DURATION" = 0 ] || { sleep "$WS_DURATION"; kill -INT "$capture" 2>/dev/null || true; } &

# A trap interrupts wait, which returns 143 with tcpdump still flushing, so ask
# again until there is no child left to wait for.
rc=0
while kill -0 "$capture" 2>/dev/null; do
	rc=0
	wait "$capture" || rc=$?
done
urc=0
wait "$upload" || urc=$?
[ "$urc" = 0 ] || { echo "webshark: upload failed ($urc)" >&2; exit "$urc"; }
case $rc in
0|130|143) echo "webshark: capture done" >&2 ;;
*) echo "webshark: tcpdump failed ($rc)" >&2; exit "$rc" ;;
esac
`

// capturePod is the pod that captures one target, in the operator's own
// namespace and on the target's node. The target pod is not touched at all -
// nothing is added to it, nothing is left behind in it, and its namespace's
// pod-security level has no say in the matter. This one's namespace does: it is
// hostPID and CAP_SYS_ADMIN, which is root on that node, and it has to be a
// namespace that allows it.
func capturePod(namespace, name string, pc *websharkv1alpha1.PacketCapture, target *corev1.Pod, image string, pull corev1.PullPolicy, uploadURL string) *corev1.Pod {
	no, yes := false, true
	root := int64(0)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				LabelCapture:                   pc.Name,
				LabelCaptureNamespace:          pc.Namespace,
				LabelTarget:                    target.Name,
				LabelTargetNamespace:           target.Namespace,
				"app.kubernetes.io/name":       "webshark-capture",
				"app.kubernetes.io/managed-by": "webshark-operator",
			},
		},
		Spec: corev1.PodSpec{
			// Straight onto the target's node, and past the scheduler with it:
			// the pod is bound before it exists, so a cordoned or tainted node
			// cannot leave a capture sitting Pending. Tolerating everything is
			// what then stops the taint manager evicting it again.
			NodeName:    target.Spec.NodeName,
			Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			// Every process on the node, which is how the target's network
			// namespace is found at all. No pid namespace is entered: the
			// capture only ever setns()es into the network one.
			HostPID:       true,
			RestartPolicy: corev1.RestartPolicyNever,
			// It talks to webshark and to nothing else - it has no business
			// with the API server, so it gets no token to reach it with.
			AutomountServiceAccountToken: &no,
			// The fifo between tcpdump and curl. It holds no data, which is
			// why it can be in memory and 1Mi of it.
			Volumes: []corev1.Volume{{
				Name: "tmp",
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium:    corev1.StorageMediumMemory,
					SizeLimit: ptrQuantity(resource.MustParse("1Mi")),
				}},
			}},
			Containers: []corev1.Container{{
				Name:            captureContainer,
				Image:           image,
				ImagePullPolicy: pull,
				Command:         []string{"/bin/sh", "-c", nodeSnifferScript},
				Env:             snifferEnv(&pc.Spec, uploadURL, podIPs(target)),
				VolumeMounts:    []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
				// Small, and no cpu limit: a throttled tcpdump drops packets,
				// and the point of the exercise is not to.
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("20m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
					Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
				},
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				SecurityContext: &corev1.SecurityContext{
					// NET_RAW is the packet socket tcpdump opens and NET_ADMIN
					// is promiscuous mode on a named interface. SYS_ADMIN is
					// setns - stepping into another pod's network namespace -
					// and SYS_PTRACE is reading /proc/<pid>/ns of a process
					// that is not ours. Everything else goes, and privileged
					// this is not: no devices, no host mounts, nothing written
					// anywhere.
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
						Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"},
					},
					RunAsUser:                &root,
					RunAsNonRoot:             &no,
					AllowPrivilegeEscalation: &no,
					ReadOnlyRootFilesystem:   &yes,
					SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
			}},
		},
	}

	if secs := int64(pc.Spec.Duration.Duration.Seconds()); secs > 0 {
		deadline := secs + int64(captureDeadlineSlack.Seconds())
		pod.Spec.ActiveDeadlineSeconds = &deadline
	}
	return pod
}

// snifferEnv is what the script reads: the capture, and the addresses to find
// the pod to take it in by.
func snifferEnv(spec *websharkv1alpha1.PacketCaptureSpec, uploadURL string, ips []string) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: "WS_URL", Value: uploadURL},
		{Name: "WS_IFACE", Value: orDefault(spec.Interface, "any")},
		{Name: "WS_FILTER", Value: spec.Filter},
		{Name: "WS_SNAPLEN", Value: fmt.Sprint(spec.Snaplen)},
		{Name: "WS_MAXPACKETS", Value: fmt.Sprint(spec.MaxPackets)},
		{Name: "WS_DURATION", Value: fmt.Sprint(int64(spec.Duration.Duration.Seconds()))},
	}
	if len(ips) > 0 {
		env = append(env, corev1.EnvVar{Name: "WS_PODIPS", Value: strings.Join(ips, " ")})
	}
	return env
}

// CapturePodName is what a target's capture pod is called. Every capture pod in
// the cluster lives in the operator's one namespace, so the name has to be
// unique across namespaces of PacketCaptures as well as of targets: the hash is
// over all four names and the readable part is only there to be read.
func CapturePodName(captureNamespace, capture, targetNamespace, target string) string {
	sum := sha1.Sum([]byte(captureNamespace + "/" + capture + "\x00" + targetNamespace + "/" + target))
	name := "pcap-" + capture + "-" + target
	if len(name) > 55 {
		name = name[:55]
	}
	return strings.TrimRight(name, "-.") + "-" + hex.EncodeToString(sum[:])[:7]
}

// podIPs is every address the pod answers on, which is what the capture looks
// for. A hostNetwork pod's address is the node's, and the namespace found by it
// is the node's too - capturing such a pod is capturing the node, because that
// is what its traffic is.
func podIPs(pod *corev1.Pod) []string {
	var ips []string
	for _, ip := range pod.Status.PodIPs {
		if ip.IP != "" {
			ips = append(ips, ip.IP)
		}
	}
	if len(ips) == 0 && pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}
	return ips
}

func ptrQuantity(q resource.Quantity) *resource.Quantity { return &q }

// captureFileName is what the capture is called in webshark. A pcap arrives
// there as a file and nothing else - no object, no labels, nothing that says
// which capture took it - so the PacketCapture's own name leads the file name,
// and typing it into webshark's filter box is what leaves one run's files.
// FileNamePrefix goes in front of it, for anyone who wants something else there.
//
// The image only accepts ^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,127}$ as a file name, so
// anything else becomes a dash and the pod name is what gives if the whole is
// too long - the capture and the namespace are worth more at that point, being
// what the file is looked up by.
//
// Nothing in the name is unique to a run: capturing the same pod twice - a
// resume, a pod coming back under the same name - writes to the same file name,
// and webshark refuses the second upload (409) until the first file is gone.
func captureFileName(prefix, capture, namespace, pod string) string {
	suffix := "-" + sanitizeName(namespace) + ".pcap"
	head := sanitizeName(prefix)
	if capture != "" {
		head += sanitizeName(capture) + "-"
	}
	head += sanitizeName(pod)
	if n := 128 - len(suffix); len(head) > n {
		head = head[:n]
	}
	name := head + suffix
	if name == "" || !isNameStart(name[0]) {
		name = "c" + name
	}
	return name
}

func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '+' || r == '-':
			return r
		}
		return '-'
	}, s)
}

func isNameStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
