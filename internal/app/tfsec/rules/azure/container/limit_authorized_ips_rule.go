package container

import (
	"github.com/aquasecurity/defsec/rules/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU008",
		BadExample: []string{`
 resource "azurerm_kubernetes_cluster" "bad_example" {
 
 }
 `},
		GoodExample: []string{`
 resource "azurerm_kubernetes_cluster" "good_example" {
     api_server_authorized_ip_ranges = [
 		"1.2.3.4/32"
 	]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		Base:           container.CheckLimitAuthorizedIps,
	})
}
