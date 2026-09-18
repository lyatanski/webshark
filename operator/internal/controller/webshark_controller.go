package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
)

const (
	websharkPort    = 8085
	capturesDir     = "/captures"
	capturesVolume  = "captures"
	websharkDefault = "ghcr.io/lyatanski/webshark:latest"
)

// WebsharkReconciler runs webshark: a claim to keep the captures in, a
// deployment reading them, a service in front, and an ingress if one is asked
// for. All four are owned by the Webshark, so they go when it does.
type WebsharkReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=webshark.io,resources=websharks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=webshark.io,resources=websharks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

// Reconcile makes what the spec asks for. A conflict is not an error worth
// logging: it is almost always this operator's own previous write, not yet in
// the cache it reads from, and the answer is to go round again.
func (r *WebsharkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result, err := r.reconcile(ctx, req)
	if apierrors.IsConflict(err) {
		return ctrl.Result{Requeue: true}, nil
	}
	return result, err
}

func (r *WebsharkReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ws := &websharkv1alpha1.Webshark{}
	if err := r.Get(ctx, req.NamespacedName, ws); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ws.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // owner references do the cleaning up
	}

	if err := r.claim(ctx, ws); err != nil {
		return ctrl.Result{}, err
	}
	deployment, err := r.deployment(ctx, ws)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.service(ctx, ws); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ingress(ctx, ws); err != nil {
		return ctrl.Result{}, err
	}

	status := ws.Status.DeepCopy()
	status.ObservedGeneration = ws.Generation
	status.ReadyReplicas = deployment.Status.ReadyReplicas
	status.ServiceURL = fmt.Sprintf("http://%s.%s.svc:%d", ws.Name, ws.Namespace, servicePort(ws))
	status.URL = externalURL(ws)
	if status.URL == "" {
		status.URL = status.ServiceURL
	}
	if status.ReadyReplicas > 0 {
		setCondition(&status.Conditions, ws.Generation, "Ready", metav1.ConditionTrue, "Running", "webshark is serving")
	} else {
		setCondition(&status.Conditions, ws.Generation, "Ready", metav1.ConditionFalse, "NotReady", "no ready replica yet")
	}
	if !apiequality.Semantic.DeepEqual(&ws.Status, status) {
		ws.Status = *status
		if err := r.Status().Update(ctx, ws); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}
	return ctrl.Result{}, nil
}

// claim is the captures directory. It is created once and then left alone: a
// PVC is next to immutable, and resizing one is the storage class's business,
// not the operator's.
func (r *WebsharkReconciler) claim(ctx context.Context, ws *websharkv1alpha1.Webshark) error {
	if ws.Spec.Storage.EmptyDir || ws.Spec.Storage.ExistingClaim != "" {
		return nil
	}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: claimName(ws), Namespace: ws.Namespace}}
	err := r.Get(ctx, client.ObjectKeyFromObject(pvc), pvc)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	size := ws.Spec.Storage.Size
	if size.IsZero() {
		size = resource.MustParse("10Gi")
	}
	pvc.Labels = labelsFor(ws)
	pvc.Spec = corev1.PersistentVolumeClaimSpec{
		AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		StorageClassName: ws.Spec.Storage.StorageClassName,
		Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: size}},
	}
	if err := controllerutil.SetControllerReference(ws, pvc, r.Scheme); err != nil {
		return err
	}
	return r.Create(ctx, pvc)
}

func (r *WebsharkReconciler) deployment(ctx context.Context, ws *websharkv1alpha1.Webshark) (*appsv1.Deployment, error) {
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: ws.Name, Namespace: ws.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		labels := labelsFor(ws)
		deployment.Labels = labels
		deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		// Recreate, not RollingUpdate: two pods cannot have the same
		// ReadWriteOnce claim, so a rolling update would deadlock on it.
		deployment.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
		deployment.Spec.Template.ObjectMeta.Labels = labels
		deployment.Spec.Template.Spec = corev1.PodSpec{
			NodeSelector: ws.Spec.NodeSelector,
			Tolerations:  ws.Spec.Tolerations,
			Containers: []corev1.Container{{
				Name:            "webshark",
				Image:           orDefault(ws.Spec.Image, websharkDefault),
				ImagePullPolicy: ws.Spec.ImagePullPolicy,
				Env:             websharkEnv(ws),
				Ports:           []corev1.ContainerPort{{Name: "http", ContainerPort: websharkPort}},
				VolumeMounts:    []corev1.VolumeMount{{Name: capturesVolume, MountPath: capturesDir}},
				Resources:       ws.Spec.Resources,
				ReadinessProbe:  httpProbe(2, 5),
				LivenessProbe:   httpProbe(10, 20),
			}},
			Volumes: []corev1.Volume{capturesVolumeFor(ws)},
		}
		return controllerutil.SetControllerReference(ws, deployment, r.Scheme)
	})
	return deployment, err
}

func (r *WebsharkReconciler) service(ctx context.Context, ws *websharkv1alpha1.Webshark) error {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ws.Name, Namespace: ws.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		service.Labels = labelsFor(ws)
		service.Annotations = ws.Spec.Service.Annotations
		service.Spec.Type = corev1.ServiceType(orDefault(string(ws.Spec.Service.Type), string(corev1.ServiceTypeClusterIP)))
		service.Spec.Selector = labelsFor(ws)
		service.Spec.Ports = []corev1.ServicePort{{
			Name:       "http",
			Port:       servicePort(ws),
			TargetPort: intstr.FromInt32(websharkPort),
			Protocol:   corev1.ProtocolTCP,
		}}
		return controllerutil.SetControllerReference(ws, service, r.Scheme)
	})
	return err
}

func (r *WebsharkReconciler) ingress(ctx context.Context, ws *websharkv1alpha1.Webshark) error {
	ingress := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: ws.Name, Namespace: ws.Namespace}}
	if !ws.Spec.Ingress.Enabled {
		err := r.Delete(ctx, ingress)
		return client.IgnoreNotFound(err)
	}
	prefix := networkingv1.PathTypePrefix
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
		ingress.Labels = labelsFor(ws)
		ingress.Annotations = ws.Spec.Ingress.Annotations
		ingress.Spec.IngressClassName = ws.Spec.Ingress.ClassName
		ingress.Spec.Rules = []networkingv1.IngressRule{{
			Host: ws.Spec.Ingress.Host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path:     orDefault(ws.Spec.Ingress.Path, "/"),
					PathType: &prefix,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: ws.Name,
						Port: networkingv1.ServiceBackendPort{Number: servicePort(ws)},
					}},
				}},
			}},
		}}
		ingress.Spec.TLS = nil
		if secret := ws.Spec.Ingress.TLSSecretName; secret != "" {
			ingress.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{ws.Spec.Ingress.Host}, SecretName: secret}}
		}
		return controllerutil.SetControllerReference(ws, ingress, r.Scheme)
	})
	return err
}

func (r *WebsharkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&websharkv1alpha1.Webshark{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Named("webshark").
		Complete(r)
}

// ---------------------------------------------------------------- helpers --

func labelsFor(ws *websharkv1alpha1.Webshark) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "webshark",
		"app.kubernetes.io/instance":   ws.Name,
		"app.kubernetes.io/managed-by": "webshark-operator",
	}
}

func claimName(ws *websharkv1alpha1.Webshark) string {
	if name := ws.Spec.Storage.ExistingClaim; name != "" {
		return name
	}
	return ws.Name + "-captures"
}

func capturesVolumeFor(ws *websharkv1alpha1.Webshark) corev1.Volume {
	if ws.Spec.Storage.EmptyDir {
		return corev1.Volume{Name: capturesVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	}
	return corev1.Volume{Name: capturesVolume, VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claimName(ws)},
	}}
}

// websharkEnv is the image's own configuration - CAPTURES first, so that
// spec.env can still override it along with everything else.
func websharkEnv(ws *websharkv1alpha1.Webshark) []corev1.EnvVar {
	env := []corev1.EnvVar{{Name: "CAPTURES", Value: capturesDir}}
	for _, e := range ws.Spec.Env {
		if e.Name == "CAPTURES" {
			env = env[:0]
		}
	}
	return append(env, ws.Spec.Env...)
}

func httpProbe(delay, period int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
			Path: "/api/captures",
			Port: intstr.FromInt32(websharkPort),
		}},
		InitialDelaySeconds: delay,
		PeriodSeconds:       period,
	}
}

func servicePort(ws *websharkv1alpha1.Webshark) int32 {
	if ws.Spec.Service.Port != 0 {
		return ws.Spec.Service.Port
	}
	return websharkPort
}

func externalURL(ws *websharkv1alpha1.Webshark) string {
	in := ws.Spec.Ingress
	if !in.Enabled || in.Host == "" {
		return ""
	}
	scheme := "http"
	if in.TLSSecretName != "" {
		scheme = "https"
	}
	return scheme + "://" + in.Host + orDefault(in.Path, "/")
}
