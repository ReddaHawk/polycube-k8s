package main

import (
	"context"
	"fmt"
	"github.com/containernetworking/plugins/pkg/ip"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net"
	"os"
)

const confFormat = `
{
	"cniVersion": "0.4.0",
	"name": "mynet",
	"type": "polycube",
	"bridge": "%s",
	"mtu": %s,
	"vclustercdir": "%s",
	"ipam": {
		"type": "host-local",
		"ranges": [
			[
				{
					"subnet": "%s"
				}
			]
		],
		"routes": [
			{ "dst": "0.0.0.0/0" }
		]
	}
}
`



func checkError(where string, err error) {
	if err != nil {
		log.Errorf(where + " " + err.Error())
		panic(where + " " + err.Error())
	}
}

// .1 is used for the gateway
func calcRangeStart(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)

	for i := 0; i < 2; i++ {
		nid = ip.NextIP(nid)
	}
	return nid
}

func main() {

	if len(os.Args) != 2 {
		panic("usage: %d polycubeConfpath")
	}


	// use the current context in kubeconfig
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Error("Creation of")
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config)


	//// creates the in-cluster config
	//config, err := rest.InClusterConfig()
	//checkError("create k8s client", err)

	checkError("create config", err)

	nodeName := os.Getenv("K8S_NODE_NAME")
	if nodeName == "" {
		panic("K8S_NODE_NAME env variable not found")
	}

	var mtu string
	mtu = os.Getenv("POLYCUBE_MTU")
	if mtu == "" {
		log.Warning("POLYCUBE_MTU env variable not found")
		mtu = "1450"
	}

	var bridgeName string
	bridgeName = os.Getenv("POLYCUBE_BRIDGE")
	if bridgeName == "" {
		log.Warning("POLYCUBE_MTU env variable not found")
		bridgeName = "br0"
	}

	var vClusterCIDR string
	vClusterCIDR = os.Getenv("POLYCUBE_VPODS_RANGE")
	if vClusterCIDR == "" {
		log.Warning("POLYCUBE_VPODS_RANGE env variable not found")
		vClusterCIDR = "10.10.0.0/16"
	}

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(),nodeName, metav1.GetOptions{})
	checkError("get node", err)

	_, podcidr, _ := net.ParseCIDR(node.Spec.PodCIDR)
	rangeStart := calcRangeStart(podcidr)

	f, err := os.Create(os.Args[1])
	checkError("create cni config file", err)
	defer f.Close()

	fmt.Fprintf(f,
		confFormat,
		bridgeName,
		mtu,
		vClusterCIDR,
		node.Spec.PodCIDR,
		rangeStart.String())
}
