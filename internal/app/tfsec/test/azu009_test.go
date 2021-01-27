package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUAKSAzureMonitor(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_kubernetes_cluster with no addon_profile define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
}`,
			mustIncludeResultCode: checks.AZUAKSAzureMonitor,
		},
		{
			name: "check azurerm_kubernetes_cluster with no oms_agent define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	addon_profile {}
}`,
			mustIncludeResultCode: checks.AZUAKSAzureMonitor,
		},
		{
			name: "check azurerm_kubernetes_cluster with oms_agent disabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	addon_profile {
		oms_agent {
			enabled = false
		}
	}
}`,
			mustIncludeResultCode: checks.AZUAKSAzureMonitor,
		},
		{
			name: "check azurerm_kubernetes_cluster with oms_agent enabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	addon_profile {
		oms_agent {
			enabled = true
		}
	}
}`,
			mustExcludeResultCode: checks.AZUAKSAzureMonitor,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
