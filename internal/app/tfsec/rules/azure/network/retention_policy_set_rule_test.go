package network

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureRetentionPeriodSet(t *testing.T) {
	expectedCode := "azure-network-retention-policy-set"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "TODO: add test name",
			source: `
 resource "azurerm_network_watcher_flow_log" "bad_watcher" {
   network_watcher_name = "bad_watcher"
   resource_group_name  = "resource-group"
 
   network_security_group_id = azurerm_network_security_group.test.id
   storage_account_id        = azurerm_storage_account.test.id
   enabled                   = true
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "TODO: add test name",
			source: `
 resource "azurerm_network_watcher_flow_log" "bad_watcher" {
   network_watcher_name = "bad_watcher"
   resource_group_name  = "resource-group"
 
   network_security_group_id = azurerm_network_security_group.test.id
   storage_account_id        = azurerm_storage_account.test.id
   enabled                   = true
 
   retention_policy {
     enabled = false
     days    = 7
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "TODO: add test name",
			source: `
 resource "azurerm_network_watcher_flow_log" "good_watcher" {
   network_watcher_name = "good_watcher"
   resource_group_name  = "resource-group"
 
   network_security_group_id = azurerm_network_security_group.test.id
   storage_account_id        = azurerm_storage_account.test.id
   enabled                   = true
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 `,
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
