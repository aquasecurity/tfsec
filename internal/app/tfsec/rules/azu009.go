package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AZUAKSAzureMonitor = "AZU009"
const AZUAKSAzureMonitorDescription = "Ensure AKS logging to Azure Monitoring is Configured"
const AZUAKSAzureMonitorImpact = "Logging provides valuable information about access and usage"
const AZUAKSAzureMonitorResolution = "Enable logging for AKS"
const AZUAKSAzureMonitorExplanation = `
Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.
`
const AZUAKSAzureMonitorBadExample = `
resource "azurerm_kubernetes_cluster" "bad_example" {
    addon_profile {}
}
`
const AZUAKSAzureMonitorGoodExample = `
resource "azurerm_kubernetes_cluster" "good_example" {
    addon_profile {
		oms_agent {
			enabled = true
		}
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUAKSAzureMonitor,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUAKSAzureMonitorDescription,
			Impact:      AZUAKSAzureMonitorImpact,
			Resolution:  AZUAKSAzureMonitorResolution,
			Explanation: AZUAKSAzureMonitorExplanation,
			BadExample:  AZUAKSAzureMonitorBadExample,
			GoodExample: AZUAKSAzureMonitorGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#oms_agent",
				"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
			},
		},
		Provider:       provider.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			addonprofileBlock := block.GetBlock("addon_profile")
			if addonprofileBlock == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing addon_profile).", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			omsagentBlock := addonprofileBlock.GetBlock("oms_agent")
			if omsagentBlock == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing oms_agent).", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			enabledAttr := omsagentBlock.GetAttribute("enabled")
			if enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() || enabledAttr == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf(
							"Resource '%s' AKS logging to Azure Monitoring is not configured (oms_agent disabled).",
							block.FullName(),
						),
						enabledAttr.Range(),
						enabledAttr,
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
