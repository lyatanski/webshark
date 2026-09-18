package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
)

// The page serves every Webshark under its own origin, at
// /webshark/<namespace>/<name>/, and links it nowhere else. Whatever got the
// browser to this page - a port-forward, a NodePort, an ingress - gets it to
// webshark too. No address webshark itself knows can promise that: its service
// is a cluster address the browser cannot follow, and its port is not the port
// this page was reached on, which is what the links used to be built from.
//
// webshark asks for everything relative to the page it was loaded from, so
// nothing in the proxied responses has to be rewritten - only the prefix taken
// off on the way in.

func websharkPath(namespace, name string) string {
	return "/webshark/" + namespace + "/" + name + "/"
}

// targetKey carries the address of the Webshark a request is for from proxy(),
// which reads the object, to the one shared ReverseProxy in front of them all.
type targetKey struct{}

func newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			target := p.In.Context().Value(targetKey{}).(*url.URL)
			p.Out.URL.Scheme = target.Scheme
			p.Out.URL.Host = target.Host
			p.Out.URL.Path, p.Out.URL.RawPath = "/"+p.In.PathValue("rest"), ""
			p.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// a browser that navigated away mid-request is not a fault
			if !errors.Is(err, context.Canceled) {
				logf.Log.WithName("ui").Error(err, "proxying to webshark", "path", r.URL.Path)
			}
			http.Error(w, "webshark is not answering: "+err.Error(), http.StatusBadGateway)
		},
	}
}

// proxy passes a request on to the Webshark its path names. The address dialled
// comes from that object's status and never from the request, so this reaches
// the websharks in the cluster and nothing else.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	ws := &websharkv1alpha1.Webshark{}
	key := client.ObjectKey{Namespace: r.PathValue("namespace"), Name: r.PathValue("name")}
	if err := s.Client.Get(r.Context(), key, ws); err != nil {
		http.Error(w, err.Error(), statusOf(err))
		return
	}
	target, err := url.Parse(serviceURL(ws))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.reverse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), targetKey{}, target)))
}

// proxyRoot is the same path without its trailing slash. It has to redirect
// rather than serve: webshark's own URLs are relative, and one directory up
// from /webshark/ns/name is the namespace, where there is nothing.
func (s *Server) proxyRoot(w http.ResponseWriter, r *http.Request) {
	to := *r.URL
	to.Path += "/"
	http.Redirect(w, r, to.RequestURI(), http.StatusFound)
}

// serviceURL is the in-cluster address of a Webshark: the one the controller
// wrote, or the one it is about to write if it has not got there yet.
func serviceURL(ws *websharkv1alpha1.Webshark) string {
	if ws.Status.ServiceURL != "" {
		return ws.Status.ServiceURL
	}
	return fmt.Sprintf("http://%s.%s.svc:%d", ws.Name, ws.Namespace, servicePort(ws))
}
