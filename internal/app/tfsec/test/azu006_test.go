package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUAKSClusterNetworkPolicy(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check if network_policy set",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	network_profile {}
}`,
			mustIncludeResultCode: checks.AZUAKSClusterNetworkPolicy,
		},
		{
			name: "check network_policy set",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	network_profile {
		network_policy = "calico"
		}
}`,
			mustExcludeResultCode: checks.AZUAKSClusterNetworkPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
