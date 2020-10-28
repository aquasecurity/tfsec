package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUAKSClusterRBACenabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_kubernetes_cluster with no role_based_access_control define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {

}`,
			mustIncludeResultCode: checks.AZUAKSClusterRBACenabled,
		},
		{
			name: "check azurerm_kubernetes_cluster with role_based_access_control disabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = false
	}
}`,
			mustIncludeResultCode: checks.AZUAKSClusterRBACenabled,
		},
		{
			name: "check azurerm_kubernetes_cluster with RBAC enabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = true
	}
}`,
			mustExcludeResultCode: checks.AZUAKSClusterRBACenabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
