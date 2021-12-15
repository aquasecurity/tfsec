package container

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingNestedChild("addon_profile.oms_agent") {
				results.Add("Resource AKS logging to Azure Monitoring is not configured.", resourceBlock)
				return
			}

			enabledAttr := resourceBlock.GetNestedAttribute("addon_profile.oms_agent.enabled")
			if enabledAttr.IsFalse() {
				results.Add("Resource AKS logging to Azure Monitoring is not configured (oms_agent disabled).", enabledAttr)
			}
			return results
		},
	})
}
