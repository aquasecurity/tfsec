package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AZUAKSAPIServerAuthorizedIPRanges(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check azurerm_kubernetes_cluster without api_server_authorized_ip_ranges defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {

}`,
			mustIncludeResultCode: rules.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster api_server_authorized_ip_ranges without value defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				api_server_authorized_ip_ranges = []

}`,
			mustIncludeResultCode: rules.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster with api_server_authorized_ip_ranges defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				api_server_authorized_ip_ranges = [
					"1.2.3.4/32"
				]
}`,
			mustExcludeResultCode: rules.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster without api_server_authorized_ip_ranges defined but private cluster enabled true",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				private_cluster_enabled = true
}`,
			mustExcludeResultCode: rules.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster with api_server_authorized_ip_ranges defined but private cluster enabled true",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				private_cluster_enabled = true
				api_server_authorized_ip_ranges = [
					"1.2.3.4/32"
				]
}`,
			mustExcludeResultCode: rules.AZUAKSAPIServerAuthorizedIPRanges,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
