// Package ui is the operator's own page: pick pods, start a capture, watch it
// land in webshark. Everything it does it does through the API - it creates
// PacketCapture objects and reads their status back, so a capture started here
// is the same object as one applied with kubectl, and can be deleted with it.
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
	"github.com/lyatanski/webshark/operator/internal/controller"
)

//go:embed web
var embedded embed.FS

// Server is the page and the handful of endpoints under it. There is no
// authentication here and there cannot usefully be: anyone who can reach it can
// read any pod's traffic. Keep it on a ClusterIP, and put an ingress in front
// only behind something that asks who is knocking.
type Server struct {
	Client client.Client
	Addr   string

	// Namespace is the operator's own, where the capture pods live. The page
	// looks there to show which pods are being captured, since a capture leaves
	// nothing at all in the pod it is capturing.
	Namespace string

	// Dir serves the page off disk instead of the copy built into the binary,
	// for working on it.
	Dir string

	// reverse is the proxy in front of every Webshark - see proxy.go.
	reverse *httputil.ReverseProxy
}

func (s *Server) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("ui")

	var web http.FileSystem
	if s.Dir != "" {
		web = http.Dir(s.Dir)
	} else {
		sub, err := fs.Sub(embedded, "web")
		if err != nil {
			return err
		}
		web = http.FS(sub)
	}

	s.reverse = newReverseProxy()

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(web))
	// webshark itself, under this page's own origin. Both methods it uses have
	// to be named: a pattern without one would match more than "GET /" does,
	// which the mux refuses to order against it.
	mux.HandleFunc("GET /webshark/{namespace}/{name}", s.proxyRoot)
	mux.HandleFunc("GET /webshark/{namespace}/{name}/{rest...}", s.proxy)
	mux.HandleFunc("POST /webshark/{namespace}/{name}/{rest...}", s.proxy)
	mux.HandleFunc("GET /api/namespaces", s.namespaces)
	mux.HandleFunc("GET /api/pods", s.pods)
	mux.HandleFunc("GET /api/websharks", s.websharks)
	mux.HandleFunc("GET /api/captures", s.captures)
	mux.HandleFunc("POST /api/captures", s.create)
	mux.HandleFunc("POST /api/pause", s.pause)
	mux.HandleFunc("DELETE /api/captures", s.delete)

	srv := &http.Server{Addr: s.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("serving", "addr", s.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// NeedLeaderElection is false: the page is read-mostly and should answer
// whichever replica the service lands on.
func (s *Server) NeedLeaderElection() bool { return false }

// ------------------------------------------------------------------ reads --

func (s *Server) namespaces(w http.ResponseWriter, r *http.Request) {
	list := &corev1.NamespaceList{}
	if err := s.Client.List(r.Context(), list); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	out := []string{}
	for _, ns := range list.Items {
		out = append(out, ns.Name)
	}
	sort.Strings(out)
	send(w, out)
}

type podView struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Phase     string            `json:"phase"`
	Node      string            `json:"node"`
	IP        string            `json:"ip"`
	Labels    map[string]string `json:"labels,omitempty"`
	Captures  []podCapture      `json:"captures,omitempty"`
}

// podCapture is a capture the operator is already running against this pod -
// which is how the page knows a pod is being captured without going through the
// PacketCapture list.
type podCapture struct {
	Capture string `json:"capture"`
	Phase   string `json:"phase"`
}

func (s *Server) pods(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := []client.ListOption{client.InNamespace(q.Get("namespace"))}
	if selector := strings.TrimSpace(q.Get("selector")); selector != "" {
		parsed, err := labels.Parse(selector)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		opts = append(opts, client.MatchingLabelsSelector{Selector: parsed})
	}

	list := &corev1.PodList{}
	if err := s.Client.List(r.Context(), list, opts...); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// A capture is a pod of the operator's own, so it is found there and not on
	// the pod being captured, which is never touched.
	capturing := map[string][]podCapture{}
	if s.Namespace != "" {
		pods := &corev1.PodList{}
		if err := s.Client.List(r.Context(), pods, client.InNamespace(s.Namespace),
			client.HasLabels{controller.LabelCapture}); err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		for i := range pods.Items {
			capturer := &pods.Items[i]
			key := capturer.Labels[controller.LabelTargetNamespace] + "/" + capturer.Labels[controller.LabelTarget]
			capturing[key] = append(capturing[key], podCapture{
				Capture: capturer.Labels[controller.LabelCapture],
				Phase:   capturerPhase(capturer),
			})
		}
	}

	out := []podView{}
	for i := range list.Items {
		pod := &list.Items[i]
		view := podView{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Phase:     string(pod.Status.Phase),
			Node:      pod.Spec.NodeName,
			IP:        pod.Status.PodIP,
			Labels:    pod.Labels,
		}
		if !pod.DeletionTimestamp.IsZero() {
			view.Phase = "Terminating"
		}
		view.Captures = append(view.Captures, capturing[pod.Namespace+"/"+pod.Name]...)
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	send(w, out)
}

// capturerPhase is a capture pod's state in the same words as the target states
// in a PacketCapture's status.
func capturerPhase(pod *corev1.Pod) string {
	switch pod.Status.Phase {
	case corev1.PodRunning:
		return string(websharkv1alpha1.CaptureCapturing)
	case corev1.PodSucceeded:
		return string(websharkv1alpha1.CaptureCompleted)
	case corev1.PodFailed:
		return string(websharkv1alpha1.CaptureFailed)
	}
	return string(websharkv1alpha1.CapturePending)
}

type websharkView struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Path is where this page serves webshark, and the only address it links it
	// at - see proxy.go. The other two are shown, not followed: URL is the
	// ingress if there is one, and ServiceURL is the cluster address the
	// captures upload to, which is what a capture's status names.
	Path       string `json:"path"`
	URL        string `json:"url"`
	ServiceURL string `json:"serviceURL"`
	Ready      bool   `json:"ready"`
}

func (s *Server) websharks(w http.ResponseWriter, r *http.Request) {
	list := &websharkv1alpha1.WebsharkList{}
	if err := s.Client.List(r.Context(), list); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	out := []websharkView{}
	for i := range list.Items {
		ws := &list.Items[i]
		out = append(out, websharkView{
			Namespace:  ws.Namespace,
			Name:       ws.Name,
			Path:       websharkPath(ws.Namespace, ws.Name),
			URL:        ws.Status.URL,
			ServiceURL: ws.Status.ServiceURL,
			Ready:      ws.Status.ReadyReplicas > 0,
		})
	}
	send(w, out)
}

// servicePort is the port webshark answers on - the same default the controller
// gives the service it makes. It is the port the proxy dials, not one any
// browser needs.
func servicePort(ws *websharkv1alpha1.Webshark) int32 {
	if ws.Spec.Service.Port != 0 {
		return ws.Spec.Service.Port
	}
	return 8085
}

func (s *Server) captures(w http.ResponseWriter, r *http.Request) {
	list := &websharkv1alpha1.PacketCaptureList{}
	if err := s.Client.List(r.Context(), list, client.InNamespace(r.URL.Query().Get("namespace"))); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[j].CreationTimestamp.Before(&list.Items[i].CreationTimestamp)
	})
	send(w, list.Items)
}

// ----------------------------------------------------------------- writes --

// createRequest is the form: the pods, and what tcpdump should do in them.
// Selectors arrive as the strings the user typed - "app=pcscf,tier=core" - and
// are parsed here rather than in the browser.
type createRequest struct {
	Namespace         string   `json:"namespace"`
	Name              string   `json:"name"`
	PodNames          []string `json:"podNames"`
	PodSelector       string   `json:"podSelector"`
	NamespaceSelector *string  `json:"namespaceSelector"`
	Interface         string   `json:"interface"`
	Filter            string   `json:"filter"`
	Duration          string   `json:"duration"`
	Snaplen           int32    `json:"snaplen"`
	MaxPackets        int64    `json:"maxPackets"`
	MaxTargets        int32    `json:"maxTargets"`
	Webshark          string   `json:"webshark"` // "namespace/name"
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if req.Namespace == "" {
		fail(w, http.StatusBadRequest, errors.New("namespace?"))
		return
	}

	capture := &websharkv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: req.Name},
		Spec: websharkv1alpha1.PacketCaptureSpec{
			PodNames:   req.PodNames,
			Interface:  req.Interface,
			Filter:     req.Filter,
			Snaplen:    req.Snaplen,
			MaxPackets: req.MaxPackets,
			MaxTargets: req.MaxTargets,
		},
	}
	if capture.Name == "" {
		capture.GenerateName = "capture-"
	}

	var err error
	if capture.Spec.PodSelector, err = parseSelector(req.PodSelector); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("podSelector: %w", err))
		return
	}
	if req.NamespaceSelector != nil {
		if capture.Spec.NamespaceSelector, err = parseSelector(*req.NamespaceSelector); err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("namespaceSelector: %w", err))
			return
		}
		if capture.Spec.NamespaceSelector == nil {
			capture.Spec.NamespaceSelector = &metav1.LabelSelector{} // every namespace
		}
	}
	// metav1.Duration is a struct, so an unset one marshals as "0s" rather than
	// being left out - and 0 means capture until the pod dies. The API's own
	// default never gets a chance to apply, so it is applied here.
	duration := 5 * time.Minute
	if req.Duration != "" {
		parsed, err := time.ParseDuration(req.Duration)
		if err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("duration: %w", err))
			return
		}
		duration = parsed
	}
	capture.Spec.Duration = metav1.Duration{Duration: duration}
	if namespace, name, ok := strings.Cut(req.Webshark, "/"); ok {
		capture.Spec.WebsharkRef = &websharkv1alpha1.WebsharkReference{Namespace: namespace, Name: name}
	}

	if err := s.Client.Create(r.Context(), capture); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	send(w, capture)
}

func (s *Server) pause(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	capture := &websharkv1alpha1.PacketCapture{}
	key := client.ObjectKey{Namespace: q.Get("namespace"), Name: q.Get("name")}
	if err := s.Client.Get(r.Context(), key, capture); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	capture.Spec.Paused = q.Get("paused") != "false"
	if err := s.Client.Update(r.Context(), capture); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	send(w, capture)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	capture := &websharkv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Namespace: q.Get("namespace"), Name: q.Get("name")},
	}
	if err := s.Client.Delete(r.Context(), capture); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	send(w, map[string]string{"deleted": capture.Name})
}

// ---------------------------------------------------------------- plumbing --

func parseSelector(s string) (*metav1.LabelSelector, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return metav1.ParseToLabelSelector(s)
}

func statusOf(err error) int {
	if status := apiStatus(err); status != 0 {
		return status
	}
	return http.StatusInternalServerError
}

func send(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logf.Log.WithName("ui").Error(err, "writing response")
	}
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"err": err.Error()})
}
