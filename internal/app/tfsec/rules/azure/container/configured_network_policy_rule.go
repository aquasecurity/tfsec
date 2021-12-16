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
		LegacyID: "AZU006",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		Base:           container.CheckConfiguredNetworkPolicy,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if networkProfileBlock := resourceBlock.GetBlock("network_profile"); networkProfileBlock.IsNotNil() {
				if networkProfileBlock.MissingChild("network_policy") {
					results.Add("Resource do not have network_policy define. network_policy should be defined to have opportunity allow or block traffic to pods", networkProfileBlock)
				}
			}

			return results
		},
	})
}
