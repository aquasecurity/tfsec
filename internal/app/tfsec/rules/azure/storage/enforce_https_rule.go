package storage

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AZU014",
		Service:   "storage",
		ShortCode: "enforce-https",
		Documentation: rule.RuleDocumentation{
			Summary:    "Storage accounts should be configured to only accept transfers that are over secure connections",
			Impact:     "Insecure transfer of data into secure accounts could be read if intercepted",
			Resolution: "Only allow secure connection for transferring data into storage accounts",
			Explanation: `
You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account. 

When you require secure transfer, any requests originating from an insecure connection are rejected. 

Microsoft recommends that you always require secure transfer for all of your storage accounts.
`,
			BadExample: []string{`
resource "azurerm_storage_account" "bad_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = false
}
`},
			GoodExample: []string{`
resource "azurerm_storage_account" "good_example" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  enable_https_traffic_only = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only",
				"https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.HasChild("enable_https_traffic_only") {

				httpsOnlyAttr := resourceBlock.GetAttribute("enable_https_traffic_only")

				if httpsOnlyAttr.IsFalse() {
					set.AddResult().
						WithDescription("Resource '%s' explicitly turns off secure transfer to storage account.", resourceBlock.FullName())
				}
			}

		},
	})
}
