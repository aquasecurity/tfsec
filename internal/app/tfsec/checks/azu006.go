package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUAKSClusterNetworkPolicy scanner.RuleCode = "AZU006"
const AZUAKSClusterNetworkPolicyDescription scanner.RuleSummary = "Ensure AKS cluster has Network Policy configured"
const AZUAKSClusterNetworkPolicyExplanation = `
The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.
`
const AZUAKSClusterNetworkPolicyBadExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	network_profile {
	  }
}
`
const AZUAKSClusterNetworkPolicyGoodExample = `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	network_profile {
	  network_policy = "calico"
	  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUAKSClusterNetworkPolicy,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUAKSClusterNetworkPolicyDescription,
			Explanation: AZUAKSClusterNetworkPolicyExplanation,
			BadExample:  AZUAKSClusterNetworkPolicyBadExample,
			GoodExample: AZUAKSClusterNetworkPolicyGoodExample,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#network_policy",
				"https://docs.microsoft.com/en-us/azure/aks/use-network-policies",
				"https://kubernetes.io/docs/concepts/services-networking/network-policies",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if networkprofileBlock := block.GetBlock("network_profile"); networkprofileBlock != nil {
				if networkprofileBlock.GetAttribute("network_policy") == nil {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf(
								"Resource '%s' do not have network_policy define. network_policy should be defined to have opportunity allow or block traffic to pods",
								block.FullName(),
							),
							networkprofileBlock.Range(),
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
