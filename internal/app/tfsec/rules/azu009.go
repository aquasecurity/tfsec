package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_kubernetes_cluster"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			addonProfileBlock := resourceBlock.GetBlock("addon_profile")
			if addonProfileBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing addon_profile).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
			if omsAgentBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing oms_agent).", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			if enabledAttr == nil || (enabledAttr.Type() == cty.Bool && enabledAttr.Value().False()) {

				res := result.New(resourceBlock).
					WithDescription(fmt.Sprintf(
						"Resource '%s' AKS logging to Azure Monitoring is not configured (oms_agent disabled).",
						resourceBlock.FullName(),
					))

				if enabledAttr != nil {
					res.WithRange(enabledAttr.Range()).
						WithAttributeAnnotation(enabledAttr)
				}

				set.Add(res)
			}

		},
	})
}
