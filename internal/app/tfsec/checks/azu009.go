package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AZUAKSAzureMonitor scanner.RuleCode = "AZU009"
const AZUAKSAzureMonitorDescription scanner.RuleSummary = "Ensure AKS logging to Azure Monitoring is Configured"
const AZUAKSAzureMonitorExplanation = `
Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.
`
const AZUAKSAzureMonitorBadExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
    addon_profile {}
}
`
const AZUAKSAzureMonitorGoodExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
    addon_profile {
		oms_agent {
			enabled = true
		}
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUAKSAzureMonitor,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUAKSAzureMonitorDescription,
			Explanation: AZUAKSAzureMonitorExplanation,
			BadExample:  AZUAKSAzureMonitorBadExample,
			GoodExample: AZUAKSAzureMonitorGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#oms_agent",
				"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			addonprofileBlock := block.GetBlock("addon_profile")
			if addonprofileBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing addon_profile).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			omsagentBlock := addonprofileBlock.GetBlock("oms_agent")
			if omsagentBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' AKS logging to Azure Monitoring is not configured (missing oms_agent).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			enabledAttr := omsagentBlock.GetAttribute("enabled")
			if enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() || enabledAttr == nil{
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf(
							"Resource '%s' AKS logging to Azure Monitoring is not configured (oms_agent disabled).",
							block.FullName(),
						),
						enabledAttr.Range(),
						enabledAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
