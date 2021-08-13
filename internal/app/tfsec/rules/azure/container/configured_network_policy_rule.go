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
		LegacyID:  "AZU006",
		Service:   "container",
		ShortCode: "configured-network-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "Ensure AKS cluster has Network Policy configured",
			Impact:     "No network policy is protecting the AKS cluster",
			Resolution: "Configure a network policy",
			Explanation: `
The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.
`,
			BadExample: []string{`
resource "azurerm_kubernetes_cluster" "bad_example" {
	network_profile {
	  }
}
`},
			GoodExample: []string{`
resource "azurerm_kubernetes_cluster" "good_example" {
	network_profile {
	  network_policy = "calico"
	  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy",
				"https://kubernetes.io/docs/concepts/services-networking/network-policies",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_kubernetes_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if networkProfileBlock := resourceBlock.GetBlock("network_profile"); networkProfileBlock.IsNotNil() {
				if networkProfileBlock.MissingChild("network_policy") {
					set.AddResult().
						WithDescription("Resource '%s' do not have network_policy define. network_policy should be defined to have opportunity allow or block traffic to pods", resourceBlock.FullName())
				}
			}

		},
	})
}
