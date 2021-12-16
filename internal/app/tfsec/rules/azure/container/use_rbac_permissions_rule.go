package container

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/azure/container"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster", "role_based_access_control"},
		Base:           container.CheckUseRbacPermissions,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("role_based_access_control") {
				results.Add("Resource defines without RBAC", resourceBlock)
				return
			}

			enabledAttr := resourceBlock.GetNestedAttribute("role_based_access_control.enabled")
			if enabledAttr.IsFalse() {
				results.Add("Resource RBAC disabled.", enabledAttr)
			}

			return results
		},
	})
}
