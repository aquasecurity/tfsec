package container

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)


func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:   "AZU006",
		Service:   "container",
		ShortCode: "configured-network-policy",
		Documentation: rule.RuleDocumentation{
			Summary:      "Ensure AKS cluster has Network Policy configured",
			Impact:       "No network policy is protecting the AKS cluster",
			Resolution:   "Configure a network policy",
			Explanation:  `
The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.
`,
			BadExample:   `
resource "azurerm_kubernetes_cluster" "bad_example" {
	network_profile {
	  }
}
`,
			GoodExample:  `
resource "azurerm_kubernetes_cluster" "good_example" {
	network_profile {
	  network_policy = "calico"
	  }
}
`,
			Links: []string{
				"https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#network_policy",
				"https://docs.microsoft.com/en-us/azure/aks/use-network-policies",
				"https://kubernetes.io/docs/concepts/services-networking/network-policies",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_kubernetes_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if networkProfileBlock := resourceBlock.GetBlock("network_profile"); networkProfileBlock != nil {
				if networkProfileBlock.GetAttribute("network_policy") == nil {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' do not have network_policy define. network_policy should be defined to have opportunity allow or block traffic to pods", resourceBlock.FullName())).
							WithRange(networkProfileBlock.Range()),
					)
				}
			}

		},
	})
}
