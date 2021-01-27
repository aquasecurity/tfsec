package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUQueueStorageAnalyticsTurnedOn scanner.RuleCode = "AZU016"
const AZUQueueStorageAnalyticsTurnedOnDescription scanner.RuleSummary = "When using Queue Services for a storage account, logging should be enabled."
const AZUQueueStorageAnalyticsTurnedOnExplanation = `
Storage Analytics logs detailed information about successful and failed requests to a storage service. 

This information can be used to monitor individual requests and to diagnose issues with a storage service. 

Requests are logged on a best-effort basis.
`
const AZUQueueStorageAnalyticsTurnedOnBadExample = `
resource "azurerm_storage_account" "bad_example" {
    name                     = "example"
    resource_group_name      = data.azurerm_resource_group.example.name
    location                 = data.azurerm_resource_group.example.location
    account_tier             = "Standard"
    account_replication_type = "GRS"
    queue_properties  {
  }
}
`
const AZUQueueStorageAnalyticsTurnedOnGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUQueueStorageAnalyticsTurnedOn,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUQueueStorageAnalyticsTurnedOnDescription,
			Explanation: AZUQueueStorageAnalyticsTurnedOnExplanation,
			BadExample:  AZUQueueStorageAnalyticsTurnedOnBadExample,
			GoodExample: AZUQueueStorageAnalyticsTurnedOnGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging",
				"https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_storage_account"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.HasChild("queue_properties") {
				queueProps := block.GetBlock("queue_properties")
				if queueProps.MissingChild("logging") {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a Queue Services storage account without Storage Analytics logging.", block.FullName()),
							block.Range(),
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}
