package main

import (
	"github.com/vishvananda/netlink"
	"net"
)

var (
	polycubeK8sInterface = "pcn_k8s"
	polycubeLBInterface = "pcn_lb"
	ipd = "172.0.0.5/24"
)

func main() {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  polycubeK8sInterface,
			Flags: net.FlagUp,
		},
		PeerName: polycubeLBInterface,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		panic(err)
	}
	_, err := netlink.LinkByName(polycubeK8sInterface)
	if err != nil {
		netlink.LinkDel(veth)
		panic(err)
	}

}