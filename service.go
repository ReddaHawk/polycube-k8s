package main

import (
	"k8s.io/apimachinery/pkg/types"
)

type backend struct {
	IP   string
	Port int32
}

type servicePortKey struct {
	Port  int32
	Proto string
}

type servicePort struct {
	Port     int32
	Proto    string
	Name     string
	Nodeport int32
	Backends map[backend]bool // backends implementing this port
}

type service struct {
	UID                   types.UID
	Name                  string
	Type                  string
	VIP                   string
	ExternalTrafficPolicy string
	Ports                 map[servicePortKey]servicePort // different ports exposed by the service
}

var (
	services map[types.UID]service
)
