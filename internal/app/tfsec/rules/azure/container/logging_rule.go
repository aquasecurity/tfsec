package container

import (
	"github.com/aquasecurity/defsec/rules/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU009",
		BadExample: []string{`
 resource "azurerm_kubernetes_cluster" "bad_example" {
     addon_profile {}
 }
 `},
		GoodExample: []string{`
 resource "azurerm_kubernetes_cluster" "good_example" {
     addon_profile {
 		oms_agent {
 			enabled = true
 		}
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		Base:           container.CheckLogging,
	})
}
