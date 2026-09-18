// webshark-operator runs webshark in a cluster and fills it with captures:
// a Webshark object is a deployment serving a directory of pcaps, and a
// PacketCapture object is tcpdump for every pod it selects, streaming into it.
//
// The same binary is what the capture pods run - the image carries tcpdump and
// curl, and the capture is a shell script over them (see
// internal/controller/sniffer.go), so there is one image to pull and one to
// trust.
package main

import (
	"flag"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	websharkv1alpha1 "github.com/lyatanski/webshark/operator/api/v1alpha1"
	"github.com/lyatanski/webshark/operator/internal/controller"
	"github.com/lyatanski/webshark/operator/internal/ui"
)

// Leases are leader election, which is the operator's own bookkeeping; the rest
// of the permissions are on the controllers that need them.
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

var (
	scheme = runtime.NewScheme()
	log    = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(websharkv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr  = flag.String("metrics-bind-address", "0", "metrics endpoint, 0 to turn it off")
		probeAddr    = flag.String("health-probe-bind-address", ":8081", "health and readiness endpoint")
		uiAddr       = flag.String("ui-bind-address", ":8080", "the page, empty to turn it off")
		leaderElect  = flag.Bool("leader-elect", false, "only one replica reconciles at a time")
		snifferImage = flag.String("sniffer-image", env("SNIFFER_IMAGE", "ghcr.io/lyatanski/webshark-operator:latest"),
			"image the capture pods run; it needs tcpdump, curl, nsenter and ip")
		namespace = flag.String("capture-namespace", env("POD_NAMESPACE", inCluster()),
			"namespace the capture pods go in - the operator's own")
		poll = flag.Duration("poll", 10*time.Second, "how often a running capture's status is re-read")
		idle = flag.Duration("idle-poll", 30*time.Second, "how often an idle PacketCapture looks for new pods")
	)
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress: *probeAddr,
		LeaderElection:         *leaderElect,
		LeaderElectionID:       "webshark-operator.webshark.io",
		// Pods and namespaces are read straight from the API server. Caching
		// them would mean an informer over every pod in the cluster for the sake
		// of a handful this operator ever touches, and that informer is the
		// largest thing a small operator usually is.
		Client: client.Options{Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.Pod{}, &corev1.Namespace{}},
		}},
	})
	if err != nil {
		log.Error(err, "starting manager")
		os.Exit(1)
	}

	if err := (&controller.WebsharkReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("webshark"),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "starting the webshark controller")
		os.Exit(1)
	}

	if err := (&controller.PacketCaptureReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Recorder:     mgr.GetEventRecorderFor("packetcapture"),
		SnifferImage: *snifferImage,
		Namespace:    *namespace,
		Poll:         *poll,
		Idle:         *idle,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "starting the packetcapture controller")
		os.Exit(1)
	}

	if *uiAddr != "" {
		// WEB= serves the page off disk instead of the copy in the binary, the
		// same as webshark itself.
		if err := mgr.Add(&ui.Server{Client: mgr.GetClient(), Addr: *uiAddr, Namespace: *namespace, Dir: os.Getenv("WEB")}); err != nil {
			log.Error(err, "starting the page")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "adding the health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "adding the readiness check")
		os.Exit(1)
	}

	log.Info("running", "sniffer", *snifferImage, "namespace", *namespace)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "running manager")
		os.Exit(1)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// inCluster is the namespace the operator is running in, read off its own
// service account, for when nothing passed it down. Captures need it - their
// pods have to go somewhere - and outside a cluster there is no answer.
func inCluster() string {
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ns))
}
