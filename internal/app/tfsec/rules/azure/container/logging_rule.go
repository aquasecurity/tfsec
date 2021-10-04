package container

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU009",
		Service:   "container",
		ShortCode: "logging",
		Documentation: rule.RuleDocumentation{
			Summary:    "Ensure AKS logging to Azure Monitoring is Configured",
			Impact:     "Logging provides valuable information about access and usage",
			Resolution: "Enable logging for AKS",
			Explanation: `
Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.
`,
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
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_kubernetes_cluster"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingNestedChild("addon_profile.oms_agent") {
				set.AddResult().
					WithDescription("Resource '%s' AKS logging to Azure Monitoring is not configured.", resourceBlock.FullName())
				return
			}

			enabledAttr := resourceBlock.GetNestedAttribute("addon_profile.oms_agent.enabled")
			if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' AKS logging to Azure Monitoring is not configured (oms_agent disabled).", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}
		},
	})
}
