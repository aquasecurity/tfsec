package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AZUAKSClusterRBACenabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_kubernetes_cluster with no role_based_access_control define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {

}`,
			mustIncludeResultCode: rules.AZUAKSClusterRBACenabled,
		},
		{
			name: "check azurerm_kubernetes_cluster with role_based_access_control disabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = false
	}
}`,
			mustIncludeResultCode: rules.AZUAKSClusterRBACenabled,
		},
		{
			name: "check azurerm_kubernetes_cluster with RBAC enabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = true
	}
}`,
			mustExcludeResultCode: rules.AZUAKSClusterRBACenabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
