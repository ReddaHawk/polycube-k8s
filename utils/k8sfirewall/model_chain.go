/*
 * firewall API
 *
 * firewall API generated from firewall.yang
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Chain struct {
	// Chain in which the rule will be inserted. Default: INGRESS.
	Name string `json:"name,omitempty"`
	// Default action if no rule matches in the ingress chain. Default is DROP.
	Default_ string       `json:"default,omitempty"`
	Stats    []ChainStats `json:"stats,omitempty"`
	Rule     []ChainRule  `json:"rule,omitempty"`
}
