package controller

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
)

// PacketCaptureReconciler runs one tcpdump for every pod a PacketCapture
// selects - in a pod of its own on that pod's node - and reports back what each
// of them is doing.
//
// It does not watch pods. Pods are read straight from the API server (the
// manager's client is configured not to cache them), and a PacketCapture with
// anything running requeues itself every Poll - a capture is a thing that lasts
// minutes, so seconds of lag in the status is not worth an informer over every
// pod in the cluster.
type PacketCaptureReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// SnifferImage is the image the capture containers run when the
	// PacketCapture does not name one. It has tcpdump and curl in it.
	SnifferImage string

	// Namespace is where the capture pods go: the operator's own, which is then
	// the one namespace in the cluster that has to allow a pod with hostPID and
	// CAP_SYS_ADMIN. Empty - the operator cannot tell what namespace it is in -
	// and a capture says so and does nothing.
	Namespace string

	// Poll is the requeue while captures are running; Idle while none are, which
	// is only there to notice pods that have since been created.
	Poll time.Duration
	Idle time.Duration
}

// +kubebuilder:rbac:groups=webshark.io,resources=packetcaptures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=webshark.io,resources=packetcaptures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=webshark.io,resources=websharks,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=create;delete,namespace=webshark
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile starts the capture pods and reads their state back. As with
// the Webshark controller, a conflict means something changed the object first -
// go round again rather than log it.
func (r *PacketCaptureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result, err := r.reconcile(ctx, req)
	if apierrors.IsConflict(err) {
		return ctrl.Result{Requeue: true}, nil
	}
	return result, err
}

func (r *PacketCaptureReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	pc := &websharkv1alpha1.PacketCapture{}
	if err := r.Get(ctx, req.NamespacedName, pc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !pc.DeletionTimestamp.IsZero() {
		// Deleting the object stops the captures: the pods running tcpdump go,
		// and the captures with them. That is the finalizer's whole job.
		return ctrl.Result{}, r.stopAll(ctx, pc)
	}

	if controllerutil.AddFinalizer(pc, CaptureFinalizer) {
		if err := r.Update(ctx, pc); err != nil {
			return ctrl.Result{}, err
		}
	}

	status := pc.Status.DeepCopy()
	status.ObservedGeneration = pc.Generation

	if r.Namespace == "" {
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionFalse, "NoCaptureNamespace",
			"the operator cannot tell what namespace it is in, so it has nowhere to put a capture pod - set POD_NAMESPACE")
		return r.finish(ctx, pc, status, ctrl.Result{RequeueAfter: r.Idle})
	}

	upload, err := r.websharkURL(ctx, pc)
	if err != nil {
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionFalse, "NoWebshark", err.Error())
		return r.finish(ctx, pc, status, ctrl.Result{RequeueAfter: r.Idle})
	}
	status.WebsharkURL = upload

	pods, truncated, err := r.targets(ctx, pc)
	if err != nil {
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionFalse, "SelectorFailed", err.Error())
		return r.finish(ctx, pc, status, ctrl.Result{RequeueAfter: r.Idle})
	}

	seen := map[string]*corev1.Pod{}
	for i := range pods {
		seen[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}

	// Existing targets first, so the list keeps its order and finished captures
	// stay on it: the file is still in webshark long after the pod is gone.
	kept := make([]websharkv1alpha1.CaptureTarget, 0, len(status.Targets)+len(pods))
	known := map[string]bool{}
	for _, t := range status.Targets {
		key := t.Namespace + "/" + t.Pod
		known[key] = true
		pod := seen[key]
		if pod == nil && (t.Phase == websharkv1alpha1.CaptureCapturing || t.Phase == websharkv1alpha1.CapturePending) {
			// Only running pods are selected, so one that has stopped being so
			// is not in the list - but it may well still be there, and a capture
			// of a pod on its way out is the one worth having.
			fetched := &corev1.Pod{}
			switch err := r.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: t.Pod}, fetched); {
			case err == nil:
				pod = fetched
			case !apierrors.IsNotFound(err):
				return ctrl.Result{}, err
			}
		}

		if err := r.observe(ctx, pc, &t, pod); err != nil {
			return ctrl.Result{}, err
		}
		// Pausing stops a capture rather than suspending it - a pcap being
		// streamed cannot be picked up where it left off - so resuming starts a
		// new capture, in a new file, for a target that is still running. Until
		// the stopped pod has gone its name is taken, and this waits.
		if t.Message == pausedMessage && !pc.Spec.Paused && pod != nil && pod.Status.Phase == corev1.PodRunning {
			fresh := websharkv1alpha1.CaptureTarget{Namespace: t.Namespace, Pod: t.Pod, Phase: websharkv1alpha1.CapturePending}
			switch skipped, err := r.start(ctx, pc, pod, &fresh, upload); {
			case err != nil:
				log.Error(err, "resuming a capture", "pod", t.Namespace+"/"+t.Pod)
			case !skipped:
				t = fresh
			}
		}
		kept = append(kept, t)
	}

	// Then pods selected now that have no target yet. A PacketCapture goes on
	// watching, so a pod created later - the next rollout, a scale-up - gets a
	// capture of its own; maxTargets is over the life of the object rather than
	// over one pass so that following a deployment around cannot go on for ever.
	for _, pod := range pods {
		if known[pod.Namespace+"/"+pod.Name] {
			continue
		}
		if len(kept) >= maxTargets(pc) {
			truncated = true
			break
		}
		target := websharkv1alpha1.CaptureTarget{
			Namespace: pod.Namespace,
			Pod:       pod.Name,
			Phase:     websharkv1alpha1.CapturePending,
		}

		switch skipped, err := r.start(ctx, pc, &pod, &target, upload); {
		case err == nil:
			if skipped {
				continue // paused, or the last one is still going; next pass
			}
		case apierrors.IsNotFound(err) || apierrors.IsConflict(err):
			continue // the namespace or the pod went; next pass
		default:
			log.Error(err, "starting a capture", "pod", pod.Namespace+"/"+pod.Name)
			target.Phase = websharkv1alpha1.CaptureFailed
			target.Message = apiMessage(err)
			r.Recorder.Eventf(pc, corev1.EventTypeWarning, "CaptureFailed",
				"tcpdump for %s/%s: %s", pod.Namespace, pod.Name, target.Message)
		}

		kept = append(kept, target)
	}

	status.Targets = kept
	status.Selected, status.Capturing, status.Completed, status.Failed = counts(kept, len(pods))

	switch {
	case pc.Spec.Paused:
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionFalse, "Paused", "the captures are stopped")
	case truncated:
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionTrue, "Truncated",
			fmt.Sprintf("more pods match than maxTargets (%d)", pc.Spec.MaxTargets))
	case len(pods) == 0:
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionTrue, "NoPods", "no running pod matches")
	default:
		setCondition(&status.Conditions, pc.Generation, "Ready", metav1.ConditionTrue, "Selected",
			fmt.Sprintf("%d pod(s) selected", len(pods)))
	}

	after := r.Idle
	if status.Capturing > 0 || pending(kept) > 0 {
		after = r.Poll
	}
	return r.finish(ctx, pc, status, ctrl.Result{RequeueAfter: after})
}

// start makes sure the pod that captures this target exists. The name is
// derived rather than random so that a pod already there can be adopted - after
// the operator restarted, or its status was cleared - instead of a second
// tcpdump being pointed at the same pod. It returns true when there is nothing
// running and nothing to start, which is a paused capture.
func (r *PacketCaptureReconciler) start(ctx context.Context, pc *websharkv1alpha1.PacketCapture, target *corev1.Pod, t *websharkv1alpha1.CaptureTarget, upload string) (bool, error) {
	name := CapturePodName(pc.Namespace, pc.Name, target.Namespace, target.Name)

	existing := &corev1.Pod{}
	switch err := r.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: name}, existing); {
	case err == nil:
		if !existing.DeletionTimestamp.IsZero() {
			// On its way out, and its name with it. Nothing to adopt and
			// nothing to start until it has gone.
			return true, nil
		}
		t.Capturer = name
		t.File = fileFromCapturer(existing)
		observeCapturePod(t, existing)
		return false, nil
	case !apierrors.IsNotFound(err):
		return false, err
	}

	if pc.Spec.Paused {
		return true, nil
	}
	if target.Spec.NodeName == "" {
		return false, fmt.Errorf("pod is not on a node")
	}
	if len(podIPs(target)) == 0 {
		return false, fmt.Errorf("pod has no address to find its network namespace by")
	}

	t.File = captureFileName(pc.Spec.FileNamePrefix, pc.Name, target.Namespace, target.Name)
	pod := capturePod(r.Namespace, name, pc, target, r.image(pc), pc.Spec.ImagePullPolicy, uploadURL(upload, t.File))
	if err := r.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		return false, err
	}
	t.Capturer = name
	t.StartedAt = ptrTime(metav1.Now())
	r.Recorder.Eventf(pc, corev1.EventTypeNormal, "CaptureStarted",
		"tcpdump on %s for %s/%s writing %s", target.Spec.NodeName, target.Namespace, target.Name, t.File)
	return false, nil
}

// observe reads the capture pod back into the target, and is also where a
// capture ends: the target no longer running, or the capture paused, deletes the
// pod that is running tcpdump. tcpdump gets a SIGINT out of the kubelet's
// SIGTERM, flushes, and the file in webshark is whole.
func (r *PacketCaptureReconciler) observe(ctx context.Context, pc *websharkv1alpha1.PacketCapture, t *websharkv1alpha1.CaptureTarget, target *corev1.Pod) error {
	if t.Capturer == "" || t.Phase == websharkv1alpha1.CaptureCompleted || t.Phase == websharkv1alpha1.CaptureFailed {
		return nil
	}

	pod := &corev1.Pod{}
	switch err := r.Get(ctx, client.ObjectKey{Namespace: r.Namespace, Name: t.Capturer}, pod); {
	case apierrors.IsNotFound(err):
		// Someone deleted it, which is a perfectly good way to stop a capture.
		t.Phase = websharkv1alpha1.CaptureCompleted
		t.Message = "stopped"
		t.FinishedAt = ptrTime(metav1.Now())
		return nil
	case err != nil:
		return err
	}

	if reason := stopReason(pc, target); reason != "" {
		if pod.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			r.Recorder.Eventf(pc, corev1.EventTypeNormal, "CaptureStopped",
				"tcpdump for %s/%s: %s", t.Namespace, t.Pod, reason)
		}
		t.Phase = websharkv1alpha1.CaptureCompleted
		t.Message = reason
		t.FinishedAt = ptrTime(metav1.Now())
		return nil
	}

	observeCapturePod(t, pod)
	return nil
}

// stopReason is why a running capture should be ended now, if it should.
// A target on its way out is still worth capturing - a pod says some of its most
// interesting things while it shuts down - so this waits for it to stop running
// rather than for it to be marked for deletion.
func stopReason(pc *websharkv1alpha1.PacketCapture, target *corev1.Pod) string {
	switch {
	case target == nil:
		return "pod gone"
	case target.Status.Phase != corev1.PodRunning:
		return "pod " + strings.ToLower(string(target.Status.Phase))
	case pc.Spec.Paused:
		return pausedMessage
	}
	return ""
}

// pausedMessage is on a target that a pause stopped, and is what tells the next
// pass that resuming should start it again.
const pausedMessage = "paused"

// stopAll deletes every pod capturing for this PacketCapture and then lets the
// object go. It is the finalizer's whole job.
func (r *PacketCaptureReconciler) stopAll(ctx context.Context, pc *websharkv1alpha1.PacketCapture) error {
	if !controllerutil.ContainsFinalizer(pc, CaptureFinalizer) {
		return nil
	}
	if r.Namespace != "" {
		list := &corev1.PodList{}
		if err := r.List(ctx, list, client.InNamespace(r.Namespace), client.MatchingLabels{
			LabelCapture:          pc.Name,
			LabelCaptureNamespace: pc.Namespace,
		}); err != nil {
			return err
		}
		for i := range list.Items {
			if err := r.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}
	controllerutil.RemoveFinalizer(pc, CaptureFinalizer)
	return r.Update(ctx, pc)
}

func (r *PacketCaptureReconciler) finish(ctx context.Context, pc *websharkv1alpha1.PacketCapture, status *websharkv1alpha1.PacketCaptureStatus, res ctrl.Result) (ctrl.Result, error) {
	if equalStatus(&pc.Status, status) {
		return res, nil
	}
	pc.Status = *status
	if err := r.Status().Update(ctx, pc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	return res, nil
}

// targets is every running pod the selectors pick, in a stable order and capped
// at maxTargets - a selector that turns out to match the cluster costs ten
// capture pods, not a thousand.
func (r *PacketCaptureReconciler) targets(ctx context.Context, pc *websharkv1alpha1.PacketCapture) ([]corev1.Pod, bool, error) {
	namespaces := []string{pc.Namespace}
	if pc.Spec.NamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(pc.Spec.NamespaceSelector)
		if err != nil {
			return nil, false, fmt.Errorf("namespaceSelector: %w", err)
		}
		list := &corev1.NamespaceList{}
		if err := r.List(ctx, list, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, false, err
		}
		namespaces = namespaces[:0]
		for _, ns := range list.Items {
			if ns.DeletionTimestamp.IsZero() {
				namespaces = append(namespaces, ns.Name)
			}
		}
	}

	podSelector, err := metav1.LabelSelectorAsSelector(pc.Spec.PodSelector)
	if err != nil {
		return nil, false, fmt.Errorf("podSelector: %w", err)
	}
	byName := map[string]bool{}
	for _, n := range pc.Spec.PodNames {
		byName[n] = true
	}

	var pods []corev1.Pod
	for _, ns := range namespaces {
		list := &corev1.PodList{}
		if err := r.List(ctx, list, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: podSelector}); err != nil {
			return nil, false, err
		}
		for _, pod := range list.Items {
			if len(byName) > 0 && !byName[pod.Name] {
				continue
			}
			if pod.Status.Phase != corev1.PodRunning || !pod.DeletionTimestamp.IsZero() {
				continue
			}
			pods = append(pods, pod)
		}
	}
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})

	limit := maxTargets(pc)
	if len(pods) > limit {
		return pods[:limit], true, nil
	}
	return pods, false, nil
}

// websharkURL is the base the captures upload to: the named Webshark, or the
// only one there is, or whatever spec.websharkURL says.
func (r *PacketCaptureReconciler) websharkURL(ctx context.Context, pc *websharkv1alpha1.PacketCapture) (string, error) {
	if u := pc.Spec.WebsharkURL; u != "" {
		if _, err := url.Parse(u); err != nil {
			return "", fmt.Errorf("websharkURL: %w", err)
		}
		return strings.TrimSuffix(u, "/"), nil
	}

	ws := &websharkv1alpha1.Webshark{}
	if ref := pc.Spec.WebsharkRef; ref != nil {
		key := client.ObjectKey{Namespace: orDefault(ref.Namespace, pc.Namespace), Name: ref.Name}
		if err := r.Get(ctx, key, ws); err != nil {
			return "", fmt.Errorf("websharkRef %s: %w", key, err)
		}
		return serviceURL(ws), nil
	}

	list := &websharkv1alpha1.WebsharkList{}
	if err := r.List(ctx, list, client.InNamespace(pc.Namespace)); err != nil {
		return "", err
	}
	if len(list.Items) == 0 {
		if err := r.List(ctx, list); err != nil {
			return "", err
		}
	}
	switch len(list.Items) {
	case 0:
		return "", fmt.Errorf("no Webshark to capture into - make one, or set spec.websharkRef")
	case 1:
		return serviceURL(&list.Items[0]), nil
	default:
		return "", fmt.Errorf("%d Websharks to choose from - set spec.websharkRef", len(list.Items))
	}
}

func (r *PacketCaptureReconciler) image(pc *websharkv1alpha1.PacketCapture) string {
	return orDefault(pc.Spec.Image, r.SnifferImage)
}

func (r *PacketCaptureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Poll == 0 {
		r.Poll = 10 * time.Second
	}
	if r.Idle == 0 {
		r.Idle = 30 * time.Second
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&websharkv1alpha1.PacketCapture{}).
		Named("packetcapture").
		Complete(r)
}

// ---------------------------------------------------------------- helpers --

// observeCapturePod is one capture pod's state read as the target's. Running is
// capturing; an exit code says whether the capture or the upload went wrong, and
// the message with it is the script's own last words, because the container's
// termination message falls back to its log.
func observeCapturePod(t *websharkv1alpha1.CaptureTarget, pod *corev1.Pod) {
	cs := containerStatus(pod, captureContainer)
	switch pod.Status.Phase {
	case corev1.PodRunning:
		t.Phase = websharkv1alpha1.CaptureCapturing
		t.Message = ""
		if cs != nil && cs.State.Running != nil {
			t.StartedAt = ptrTime(cs.State.Running.StartedAt)
		}
	case corev1.PodSucceeded:
		t.Phase = websharkv1alpha1.CaptureCompleted
		t.Message = ""
		t.FinishedAt = finishedAt(cs)
	case corev1.PodFailed:
		t.Phase = websharkv1alpha1.CaptureFailed
		t.Message = capturerMessage(pod, cs)
		t.FinishedAt = finishedAt(cs)
	default:
		// Pending: the image is being pulled, or the kubelet has turned it down
		// for want of room on the node, which it says here.
		t.Phase = websharkv1alpha1.CapturePending
		if cs != nil && cs.State.Waiting != nil {
			t.Message = clip(strings.TrimSpace(cs.State.Waiting.Reason + " " + cs.State.Waiting.Message))
		} else {
			t.Message = clip(strings.TrimSpace(pod.Status.Reason + " " + pod.Status.Message))
		}
	}
}

// capturerMessage is why a capture pod failed: the container's own exit if it
// got as far as one, and the pod's if it did not - activeDeadlineSeconds and a
// kubelet that refused the pod both speak there.
func capturerMessage(pod *corev1.Pod, cs *corev1.ContainerStatus) string {
	if cs != nil && cs.State.Terminated != nil {
		term := cs.State.Terminated
		return clip(strings.TrimSpace(fmt.Sprintf("%s (exit %d) %s", term.Reason, term.ExitCode, term.Message)))
	}
	return clip(strings.TrimSpace(pod.Status.Reason + " " + pod.Status.Message))
}

func containerStatus(pod *corev1.Pod, name string) *corev1.ContainerStatus {
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == name {
			return &pod.Status.ContainerStatuses[i]
		}
	}
	return nil
}

func finishedAt(cs *corev1.ContainerStatus) *metav1.Time {
	if cs != nil && cs.State.Terminated != nil {
		return ptrTime(cs.State.Terminated.FinishedAt)
	}
	return ptrTime(metav1.Now())
}

// fileFromCapturer reads the capture's file name back off the container that
// was given it, which is where it was written down: the upload URL ends in it,
// so a lost status costs nothing.
func fileFromCapturer(pod *corev1.Pod) string {
	for _, c := range pod.Spec.Containers {
		if c.Name == captureContainer {
			return fileFrom(c.Env)
		}
	}
	return ""
}

func fileFrom(env []corev1.EnvVar) string {
	for _, e := range env {
		if e.Name == "WS_URL" {
			if u, err := url.Parse(e.Value); err == nil {
				return u.Query().Get("f")
			}
		}
	}
	return ""
}

func uploadURL(base, file string) string {
	return base + "/api/file?f=" + url.QueryEscape(file)
}

func serviceURL(ws *websharkv1alpha1.Webshark) string {
	if ws.Status.ServiceURL != "" {
		return ws.Status.ServiceURL
	}
	port := ws.Spec.Service.Port
	if port == 0 {
		port = 8085
	}
	return fmt.Sprintf("http://%s.%s.svc:%d", ws.Name, ws.Namespace, port)
}

// maxTargets is how many pods one PacketCapture will ever touch.
func maxTargets(pc *websharkv1alpha1.PacketCapture) int {
	if pc.Spec.MaxTargets <= 0 {
		return 10
	}
	return int(pc.Spec.MaxTargets)
}

func counts(targets []websharkv1alpha1.CaptureTarget, selected int) (sel, capturing, completed, failed int32) {
	for _, t := range targets {
		switch t.Phase {
		case websharkv1alpha1.CaptureCapturing:
			capturing++
		case websharkv1alpha1.CaptureCompleted:
			completed++
		case websharkv1alpha1.CaptureFailed:
			failed++
		}
	}
	return int32(selected), capturing, completed, failed
}

func pending(targets []websharkv1alpha1.CaptureTarget) int {
	n := 0
	for _, t := range targets {
		if t.Phase == websharkv1alpha1.CapturePending {
			n++
		}
	}
	return n
}

// apiMessage is the API server's complaint, trimmed to something that fits in a
// status. A pod-security refusal is the one worth reading: it names the policy
// and the capability it will not have.
func apiMessage(err error) string { return clip(err.Error()) }

func clip(msg string) string {
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

func setCondition(conditions *[]metav1.Condition, generation int64, kind string, state metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               kind,
		Status:             state,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

func ptrTime(t metav1.Time) *metav1.Time { return &t }

// equalStatus keeps the operator from writing a status identical to the one
// already there, which every poll would otherwise do. Conditions carry a
// transition time, but SetStatusCondition only moves it when the status changes.
func equalStatus(a, b *websharkv1alpha1.PacketCaptureStatus) bool {
	return apiequality.Semantic.DeepEqual(a, b)
}
