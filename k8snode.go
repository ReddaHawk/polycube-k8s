package main

import "net"

type k8sNode struct {
	Name        string
	PrivateIP   net.IP
	PrivateMask net.IPMask
	PublicIP    net.IP
	RouterIP    *net.IPNet
	PodCIDR     *net.IPNet
	VPodCIDR    *net.IPNet
}

// node.Node interface
func (n *k8sNode) GetName() string {
	return n.Name
}
