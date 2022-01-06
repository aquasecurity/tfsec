package container

import (
	"github.com/aquasecurity/defsec/rules/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AZU007",
		BadExample: []string{`
 resource "azurerm_kubernetes_cluster" "bad_example" {
 	role_based_access_control {
 		enabled = false
 	}
 }
 `},
		GoodExample: []string{`
 resource "azurerm_kubernetes_cluster" "good_example" {
 	role_based_access_control {
 		enabled = true
 	}
 }
 `},
		Links: []string{
			"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster", "role_based_access_control"},
		Base:           container.CheckUseRbacPermissions,
	})
}
