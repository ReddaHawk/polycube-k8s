/*
 * simplebridge API
 *
 * simplebridge API generated from simplebridge.yang
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Simplebridge struct {
	// Name of the simplebridge service
	Name string `json:"name,omitempty"`
	// UUID of the Cube
	Uuid string `json:"uuid,omitempty"`
	// Type of the Cube (TC, XDP_SKB, XDP_DRV)
	Type_ string `json:"type,omitempty"`
	ServiceName string `json:"service-name,omitempty"`
	// Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)
	Loglevel string `json:"loglevel,omitempty"`
	// Entry of the ports table
	Ports []Ports `json:"ports,omitempty"`
	// Defines if the service is visible in Linux
	Shadow bool `json:"shadow,omitempty"`
	// Defines if all traffic is sent to Linux
	Span bool `json:"span,omitempty"`
	Fdb *Fdb `json:"fdb,omitempty"`
}
