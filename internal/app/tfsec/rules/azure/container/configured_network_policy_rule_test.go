package container
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AZUAKSClusterNetworkPolicy(t *testing.T) {
// 	expectedCode := "azure-container-configured-network-policy"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check if network_policy set",
// 			source: `
// resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
// 	network_profile {}
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check network_policy set",
// 			source: `
// resource "azurerm_kubernetes_cluster" "my-aks-cluster" {
// 	network_profile {
// 		network_policy = "calico"
// 		}
// }`,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
