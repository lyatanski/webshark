package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebsharkSpec is one webshark deployment: the pod, the directory of captures
// behind it, and how it is reached. The operator owns everything it makes here,
// so deleting the Webshark deletes the lot.
type WebsharkSpec struct {
	// Image is the webshark container image.
	// +kubebuilder:default="ghcr.io/lyatanski/webshark:latest"
	Image string `json:"image,omitempty"`

	// ImagePullPolicy for that image.
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Storage is the directory webshark serves. A PersistentVolumeClaim by
	// default; EmptyDir instead means the captures go when the pod does.
	// +optional
	Storage WebsharkStorage `json:"storage,omitempty"`

	// Service is how the pod is published inside the cluster.
	// +optional
	Service WebsharkService `json:"service,omitempty"`

	// Ingress, if enabled, publishes it outside.
	// +optional
	Ingress WebsharkIngress `json:"ingress,omitempty"`

	// Env is added to the webshark container - SHARKD_SESSIONS, SHARKD_IDLE,
	// SCAN_FRAMES and the rest of what the image reads.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Resources for the webshark container. sharkd holds a dissected capture in
	// memory, so the limit is what bounds how large a file can be opened.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// WebsharkStorage is where the captures live.
type WebsharkStorage struct {
	// EmptyDir keeps them in the pod instead of a claim - fine for a look at
	// live traffic, gone at the next restart.
	// +optional
	EmptyDir bool `json:"emptyDir,omitempty"`

	// Size of the claim.
	// +kubebuilder:default="10Gi"
	Size resource.Quantity `json:"size,omitempty"`

	// StorageClassName of the claim; unset means the cluster default.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// ExistingClaim is used as-is instead of one being created.
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`
}

// WebsharkService is the ClusterIP (or whatever type) in front of the pod.
type WebsharkService struct {
	// +kubebuilder:default=ClusterIP
	Type corev1.ServiceType `json:"type,omitempty"`
	// +kubebuilder:default=8085
	Port int32 `json:"port,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// WebsharkIngress publishes the service.
type WebsharkIngress struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// +optional
	ClassName *string `json:"className,omitempty"`
	// +optional
	Host string `json:"host,omitempty"`
	// +optional
	Path string `json:"path,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// TLSSecretName, if set, terminates TLS for Host with that secret.
	// +optional
	TLSSecretName string `json:"tlsSecretName,omitempty"`
}

// WebsharkStatus reports what the operator made of the spec.
type WebsharkStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL is where the captures can be read - the ingress if there is one,
	// otherwise the in-cluster service.
	// +optional
	URL string `json:"url,omitempty"`

	// ServiceURL is always the in-cluster one, and is what captures upload to.
	// +optional
	ServiceURL string `json:"serviceURL,omitempty"`

	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ws
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.status.url`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Webshark is a webshark deployment the operator keeps up.
type Webshark struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebsharkSpec   `json:"spec,omitempty"`
	Status WebsharkStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebsharkList is a list of Websharks.
type WebsharkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Webshark `json:"items"`
}

func init() { SchemeBuilder.Register(&Webshark{}, &WebsharkList{}) }
