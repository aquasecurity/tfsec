package container

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUAKSAzureMonitor(t *testing.T) {
	expectedCode := "azure-container-logging"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_kubernetes_cluster with no addon_profile define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check azurerm_kubernetes_cluster with no oms_agent define",
			source: `
resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
	addon_profile {}
}`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
