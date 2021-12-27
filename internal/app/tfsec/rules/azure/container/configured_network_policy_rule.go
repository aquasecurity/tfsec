package container

import (
	"github.com/aquasecurity/defsec/rules/azure/container"
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_kubernetes_cluster"},
		Base:           container.CheckConfiguredNetworkPolicy,
	})
}
