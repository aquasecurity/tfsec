package storage

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AZUQueueStorageAnalyticsTurnedOn(t *testing.T) {
	expectedCode := "azure-storage-queue-services-logging-enabled"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check queue services storage account without analytics logging causes failure",
			source: `
 resource "azurerm_storage_account" "good_example" {
     name                     = "example"
     resource_group_name      = data.azurerm_resource_group.example.name
     location                 = data.azurerm_resource_group.example.location
     account_tier             = "Standard"
     account_replication_type = "GRS"
     queue_properties  {
 
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check queue services storage account with analytics logging enabled passes",
			source: `
 resource "azurerm_storage_account" "good_example" {
     name                     = "example"
     resource_group_name      = data.azurerm_resource_group.example.name
     location                 = data.azurerm_resource_group.example.location
     account_tier             = "Standard"
     account_replication_type = "GRS"
     queue_properties  {
     logging {
         delete                = true
         read                  = true
         write                 = true
         version               = "1.0"
         retention_policy_days = 10
     }
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
