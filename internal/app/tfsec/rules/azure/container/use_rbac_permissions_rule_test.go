package container

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUAKSClusterRBACenabled(t *testing.T) {
	expectedCode := "azure-container-use-rbac-permissions"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_kubernetes_cluster with role_based_access_control disabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = false
	}
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_kubernetes_cluster with RBAC enabled",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	role_based_access_control {
		enabled = true
	}
}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
