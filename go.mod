module github.com/polycube-network/polycube/src/components/k8s

go 1.15

require (
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.9.1
	github.com/go-logr/logr v0.3.0
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.3
	github.com/prometheus/common v0.10.0
	github.com/sirupsen/logrus v1.6.0
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	golang.org/x/net v0.0.0-20201006153459-a7d1128ccaa0
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	sigs.k8s.io/controller-runtime v0.7.2
)
