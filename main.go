/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"github.com/prometheus/common/log"
	"net/http"
	"os"
	"runtime"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	k8sdispatcher "github.com/polycube-network/polycube/src/components/k8s/utils/k8sdispatcher"
	lbrp "github.com/polycube-network/polycube/src/components/k8s/utils/lbrp"
	router "github.com/polycube-network/polycube/src/components/k8s/utils/router"
	simplebridge "github.com/polycube-network/polycube/src/components/k8s/utils/simplebridge"

	"github.com/polycube-network/polycube/src/components/k8s/controllers"
	//+kubebuilder:scaffold:imports
)
const (
	basePath             = "http://127.0.0.1:9000/polycube/v1"
	vxlanInterface       = "pcn_vxlan"
	stackInterface       = "pcn_stack"
	routerInterface      = "pcn_router"
	polycubeK8sInterface = "pcn_k8s"
	polycubeLBInterface  = "pcn_lb"
	k8sdispatcherName        = "k8sdispatcher"

	vPodsRangeDefault            = "10.10.0.0/16"
	vtepsRangeDefault            = "10.18.0.0/16"
	serviceClusterIPRangeDefault = "10.96.0.0/12"
	serviceNodePortRangeDefault  = "30000-32767"
)

var (
	// node where this instance is running
	nodeName string


	k8sdispatcherAPI 	*k8sdispatcher.K8sdispatcherApiService
	lbrpAPI 			*lbrp.LbrpApiService
	routerAPI			*router.RouterApiService
	simplebridgeAPI 	*simplebridge.SimplebridgeApiService

	nodeIP string

	)

var (
	scheme   = k8sruntime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	cfgK8sdispatcher := k8sdispatcher.Configuration{BasePath: basePath}
	srK8sdispatcher  := k8sdispatcher.NewAPIClient(&cfgK8sdispatcher)
	k8sdispatcherAPI  = srK8sdispatcher.K8sdispatcherApi

	cfglbrp := lbrp.Configuration{BasePath: basePath}
	srlbrp  := lbrp.NewAPIClient(&cfglbrp)
	lbrpAPI  = srlbrp.LbrpApi

	cfgrouter := router.Configuration{BasePath: basePath}
	srRouter  := router.NewAPIClient(&cfgrouter)
	routerAPI  = srRouter.RouterApi

	cfgsimplebridge := simplebridge.Configuration{BasePath: basePath}
	srSimplebridge  := simplebridge.NewAPIClient(&cfgsimplebridge)
	simplebridgeAPI  = srSimplebridge.SimplebridgeApi

	nodeName = os.Getenv("K8s_NODE_NAME")
	if nodeName == "" {
		panic("K8S_NODE_NAME env variable not found")
	}

	setupLog.Info("Running in node: %s",nodeName)

	services = make(map[types.UID]service)

	// wait until polycubed is ready
	// TODO: implement backoff
	i := 0
	for i = 0; i < 30; {
		if _, err := http.Get("http://127.0.0.1:9000"); err == nil {
			log.Debug("polycubed is ready")
			break
		}
		log.Debug("Waiting for polycubed")
		time.Sleep(5 * time.Second)
	}

	if i == 30 {
		log.Error("error contacting polycubed")
		return
	}


	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "51cfa751.polycube.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.EndpointsReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Endpoints"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Endpoints")
		os.Exit(1)
	}
	if err = (&controllers.NodeReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Node"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Node")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
