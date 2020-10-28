package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUAKSAPIServerAuthorizedIPRanges(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check azurerm_kubernetes_cluster without api_server_authorized_ip_ranges defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {

}`,
			mustIncludeResultCode: checks.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster api_server_authorized_ip_ranges without value defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				api_server_authorized_ip_ranges = []

}`,
			mustIncludeResultCode: checks.AZUAKSAPIServerAuthorizedIPRanges,
		},
		{
			name: "check azurerm_kubernetes_cluster with api_server_authorized_ip_ranges defined",
			source: `
			resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
				api_server_authorized_ip_ranges = [
					"1.2.3.4/32"
				]
}`,
			mustExcludeResultCode: checks.AZUAKSAPIServerAuthorizedIPRanges,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
