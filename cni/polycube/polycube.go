package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/polycube-network/polycube/src/components/k8s/utils"
	lbrp "github.com/polycube-network/polycube/src/components/k8s/utils/lbrp"
	simplebridge "github.com/polycube-network/polycube/src/components/k8s/utils/simplebridge"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
)

type NetConf struct {
	types.NetConf
	MTU          int    `json:"mtu"`
	VClusterCIDR string `json:"vclustercdir"`
	BridgeName   string `json:"bridge"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

const (
	basePath             = "http://127.0.0.1:9000/polycube/v1"
	polycubeK8sInterface = "pcn_k8s"
)

var (

	simplebridgeAPI		 *simplebridge.SimplebridgeApiService
	lbrpAPI				 *lbrp.LbrpApiService

)

func init() {
	log.SetLevel(log.DebugLevel)
	file, err := os.OpenFile("logrus.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.Info("Failed to log to file")
	}
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	// init simplebrige API
	cfgSimplebridge := simplebridge.Configuration{BasePath: basePath}
	srSimplebridge := simplebridge.NewAPIClient(&cfgSimplebridge)
	simplebridgeAPI = srSimplebridge.SimplebridgeApi

	// init lbrp API
	cfgLbrp := lbrp.Configuration{BasePath: basePath}
	srLbrp := lbrp.NewAPIClient(&cfgLbrp)
	lbrpAPI = srLbrp.LbrpApi
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}

	return n, n.CNIVersion, nil
}


func createLbrp(ip string) (string , error) {
	// create lbrp with pod ip so it can be referenced by operator
	name := "lbrp-" + ip


	lbrpPortBackend := lbrp.Ports{
		Name: "to_switch",
		Type_: "BACKEND",
	}
	lbrpPortFrontend := lbrp.Ports{
		Name: "to_pod",
		Type_: "FRONTEND",
	}
	lbrpPorts := []lbrp.Ports{lbrpPortFrontend,lbrpPortBackend}
	lb := lbrp.Lbrp{
		Name: name,
		Ports: lbrpPorts,
		Loglevel: "DEBUG",
	}
	if response, err := lbrpAPI.CreateLbrpByID(context.TODO(), name, lb); err != nil {
		log.Errorf("An error occurred while trying to create lbrp %s: error: %s, response: %+v", name, err, response)
		return "" ,err
	}
	log.Infof("lbrp %s successfully created", name)


	return name, nil
}

func deleteLbrp(name string) {
	if response, err := lbrpAPI.DeleteLbrpByID(context.TODO(), name); err != nil {
		log.Errorf("Could not delete firewall %s; response: %+v; error: %s", name, response, err)
	}
}

func setupVeth(netns ns.NetNS, ifName string, mtu int) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	return hostIface, contIface, nil
}



// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*NetConf, error) {
	conf := NetConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result. This will parse, validate, and place the
	// previous result object into conf.PrevResult. If you need to modify
	// or inspect the PrevResult you will need to convert it to a concrete
	// versioned Result struct.
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, fmt.Errorf("could not parse prevResult: %v", err)
	}
	// End previous result parsing

	if conf.MTU == 0 {
		return nil, fmt.Errorf("MTU must be specified")
	}

	if conf.BridgeName == "" {
		return nil, fmt.Errorf("Bridge name must be specified")
	}

	if conf.VClusterCIDR == "" {
		return nil, fmt.Errorf("VClusterCIDR must be specified")
	}

	return &conf, nil
}

// Duplicate an ip
func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Debug("cmdAdd requested")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	// run IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(conf.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	var ip net.IP
	for _, ip_i := range result.IPs {
		if ip_i.Version == "4" {
			log.Debugf("Got %s ipv4", ip_i.Address.IP)
			ip = ip_i.Address.IP
		}

		if ip_i.Interface == nil {
			log.Debugf("Skipping")
			continue
		}
	}


	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := setupVeth(netns, args.IfName, conf.MTU)
	if err != nil {
		return err
	}

	result = &current.Result{
		Interfaces: []*current.Interface{
			hostInterface,
			containerInterface,
		},
	}
	// create port on switch
	portName := args.ContainerID[0:10]
	log.Info("ip is: "+ ip.String())
	log.Info("port name is: "+portName)

	switchPort := simplebridge.Ports{Name: portName}
	if _, err := simplebridgeAPI.CreateSimplebridgePortsByID(context.TODO(),conf.BridgeName,portName,switchPort); err != nil {
		return fmt.Errorf("Error creating port on switch: %s", err)
	}


	// create lbrp
	nameLbrp , err := createLbrp(ip.String())
	if err != nil {
		return fmt.Errorf("Error creating lbrp: %s", err)
	}

	log.Debug("Connecting bridge <-> lbrp: " +nameLbrp+":toSwitch " + conf.BridgeName+":"+portName)
	if _, err := lbrpAPI.UpdateLbrpPortsPeerByID(nil,
		nameLbrp, "to_switch", utils.CreatePeer(conf.BridgeName,portName)); err != nil {
		return fmt.Errorf("Error connecting lbrp %s to simplebridge %s:%s: %s ",nameLbrp,conf.BridgeName,portName, err.Error())
	}
	if _, err := simplebridgeAPI.UpdateSimplebridgePortsPeerByID(context.TODO(),
		conf.BridgeName, portName, utils.CreatePeer(nameLbrp,"to_switch")); err != nil {
		return fmt.Errorf("Error connecting simplebrige to lbrp %s: %s",nameLbrp, err.Error())
	}
	log.Debug("Connecting container <-> lbrp: "+nameLbrp+ hostInterface.Name)
	var mac net.HardwareAddr

	gwLink, err := netlink.LinkByName(polycubeK8sInterface)
	if err != nil {
		fmt.Errorf("failed to lookup %s: %v", polycubeK8sInterface, err)
	}
	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		// configure interface "by hand" because ipam.ConfigureIface does not do
		// what we want to
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}

		mac = link.Attrs().HardwareAddr

		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set %q UP: %v", args.IfName, err)
		}

		// add ip with a /32 mask
		ipnet := net.IPNet{IP: ip, Mask: net.IPv4Mask(0xFF, 0xFF, 0xFF, 0xFF)}
		addr := &netlink.Addr{IPNet: &ipnet, Label: ""}
		if err = netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("Error configuring iface")
		}
		gw := dupIP(ip)
		gw = gw.To4()
		gw[3] = 0x01
		gwNet := net.IPNet{IP: gw, Mask: net.IPv4Mask(0xFF, 0xFF, 0xFF, 0xFF)}
		// add link local route to reach gw
		gwRoute := netlink.Route{
			Dst:       &gwNet,
			Scope:     unix.RT_SCOPE_LINK,
			LinkIndex: link.Attrs().Index}
		if err := netlink.RouteAdd(&gwRoute); err != nil {
			log.Error("error adding routing table to srciprewritten")
			return err
		}

		defaultRoute := netlink.Route{
			Dst: nil,
			Gw:  gw,
		}
		if err := netlink.RouteAdd(&defaultRoute); err != nil {
			log.Error("error adding routing table to srciprewritten")
			return err
		}
		// add arp entry to reach gateway
		arpentry := netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           gw,
			HardwareAddr: gwLink.Attrs().HardwareAddr,
		}

		if err := netlink.NeighAdd(&arpentry); err != nil {
			log.Error("Error adding static arp entry")
			return err
		}
		return nil

	}); err != nil {
		return err
	}

	// todo create arp entry

	return types.PrintResult(result, conf.CNIVersion)
}

func main() {
	skel.PluginMain(cmdAdd, nil, nil, version.All, "Polycube cni plugin")
}