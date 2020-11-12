package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AZUQueueStorageAnalyticsTurnedOn(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
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
			mustIncludeResultCode: checks.AZUQueueStorageAnalyticsTurnedOn,
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
			mustExcludeResultCode: checks.AZUQueueStorageAnalyticsTurnedOn,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
