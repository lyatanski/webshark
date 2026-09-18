package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PacketCaptureSpec selects pods and says what to capture in them. Each selected
// pod gets one tcpdump, in a pod of the operator's own on the same node, which
// steps into the target's network namespace and streams the pcap straight into a
// webshark instance.
//
// The pod being captured is not touched at all: nothing is added to it, nothing
// is left in it, and nothing is written to the node either.
type PacketCaptureSpec struct {
	// NamespaceSelector picks the namespaces to look in. Left out, only this
	// PacketCapture's own namespace is searched; empty ({}), every namespace.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector picks pods by label. Left out, every running pod in those
	// namespaces matches - MaxTargets is what stops that being the whole cluster.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// PodNames picks pods by name, and-ed with PodSelector when both are given.
	// +optional
	PodNames []string `json:"podNames,omitempty"`

	// Interface tcpdump listens on. "any" is every interface the pod has, which
	// is what you want unless the pod has more than one and you know which.
	// +kubebuilder:default=any
	Interface string `json:"interface,omitempty"`

	// Filter is a pcap filter, e.g. "udp port 5060 or tcp port 3868". Applied by
	// tcpdump in the pod, so what it drops never crosses the network.
	// +optional
	Filter string `json:"filter,omitempty"`

	// Snaplen is bytes captured per packet; 0 is the whole packet.
	// +optional
	Snaplen int32 `json:"snaplen,omitempty"`

	// Duration is the longest a capture runs, rather than the only way one ends:
	// deleting the PacketCapture or pausing it stops the captures, and so does
	// the pod being captured going away.
	// 0 is until the target pod dies, which wants MaxPackets or a tight Filter.
	// +kubebuilder:default="5m"
	Duration metav1.Duration `json:"duration,omitempty"`

	// MaxPackets ends a capture after that many packets. 0 is no limit.
	// +optional
	MaxPackets int64 `json:"maxPackets,omitempty"`

	// MaxTargets caps how many pods one PacketCapture will ever touch - over its
	// whole life, not per pass, because a capture goes on watching: a pod
	// created later that matches gets a capture of its own, which is how a
	// crashlooping pod's traffic is caught. A selector wider than intended
	// therefore costs ten capture pods and not a hundred, and the way to stop it
	// following a deployment around is Paused, or deleting it.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	MaxTargets int32 `json:"maxTargets,omitempty"`

	// Paused stops the captures: the running ones end, and no new ones start.
	// Resuming starts fresh captures, in new files, for the pods still running -
	// a pcap being streamed cannot be picked up where it left off.
	// +optional
	Paused bool `json:"paused,omitempty"`

	// WebsharkRef names the Webshark the pcaps go to. Left out, the operator
	// takes the only Webshark in this namespace, or the only one in the cluster.
	// +optional
	WebsharkRef *WebsharkReference `json:"websharkRef,omitempty"`

	// WebsharkURL uploads somewhere else entirely - any host speaking webshark's
	// POST /api/file?f=<name>. Wins over WebsharkRef.
	// +optional
	WebsharkURL string `json:"websharkURL,omitempty"`

	// Image runs the capture: it needs tcpdump, curl, nsenter and ip. Defaults to
	// the operator's own image, which has all four.
	// +optional
	Image string `json:"image,omitempty"`

	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// FileNamePrefix goes in front of the generated capture file name. The name
	// is <prefix><pod>-<namespace>-<date>.pcap, and webshark only accepts
	// [A-Za-z0-9 ._+-].
	// +optional
	FileNamePrefix string `json:"fileNamePrefix,omitempty"`
}

// WebsharkReference points at a Webshark object.
type WebsharkReference struct {
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// CapturePhase is where one pod's capture has got to.
// +kubebuilder:validation:Enum=Pending;Capturing;Completed;Failed
type CapturePhase string

const (
	CapturePending   CapturePhase = "Pending"
	CaptureCapturing CapturePhase = "Capturing"
	CaptureCompleted CapturePhase = "Completed"
	CaptureFailed    CapturePhase = "Failed"
)

// CaptureTarget is one pod being captured, and the file it is writing.
type CaptureTarget struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	// Capturer is the pod running tcpdump for this target - in the operator's own
	// namespace, on this target's node. `kubectl logs` on it is what tcpdump had
	// to say, and deleting it stops the capture.
	// +optional
	Capturer string `json:"capturer,omitempty"`
	// File is the capture in webshark, appearing there as it is written.
	File  string       `json:"file"`
	Phase CapturePhase `json:"phase"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

// PacketCaptureStatus is one line per pod and the counts over them.
type PacketCaptureStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	// +listType=atomic
	Targets []CaptureTarget `json:"targets,omitempty"`
	// +optional
	Selected int32 `json:"selected,omitempty"`
	// +optional
	Capturing int32 `json:"capturing,omitempty"`
	// +optional
	Completed int32 `json:"completed,omitempty"`
	// +optional
	Failed int32 `json:"failed,omitempty"`
	// +optional
	WebsharkURL string `json:"websharkURL,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pcap
// +kubebuilder:printcolumn:name="Targets",type=integer,JSONPath=`.status.selected`
// +kubebuilder:printcolumn:name="Capturing",type=integer,JSONPath=`.status.capturing`
// +kubebuilder:printcolumn:name="Done",type=integer,JSONPath=`.status.completed`
// +kubebuilder:printcolumn:name="Failed",type=integer,JSONPath=`.status.failed`
// +kubebuilder:printcolumn:name="Webshark",type=string,JSONPath=`.status.websharkURL`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PacketCapture is tcpdump in every pod it selects, streaming into webshark.
type PacketCapture struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PacketCaptureSpec   `json:"spec,omitempty"`
	Status PacketCaptureStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PacketCaptureList is a list of PacketCaptures.
type PacketCaptureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PacketCapture `json:"items"`
}

func init() { SchemeBuilder.Register(&PacketCapture{}, &PacketCaptureList{}) }
