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
		LegacyID:  "AZU013",
		Service:   "storage",
		ShortCode: "allow-microsoft-service-bypass",
		Documentation: rule.RuleDocumentation{
			Summary:    "Trusted Microsoft Services should have bypass access to Storage accounts",
			Impact:     "Trusted Microsoft Services won't be able to access storage account unless rules set to allow",
			Resolution: "Allow Trusted Microsoft Services to bypass",
			Explanation: `
Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. 

To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules
`,
			BadExample: []string{`
resource "azurerm_storage_account" "bad_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
	bypass                     = ["Metrics"]
  }

  tags = {
    environment = "staging"
  }
}

resource "azurerm_storage_account_network_rules" "test" {
  resource_group_name  = azurerm_resource_group.test.name
  storage_account_name = azurerm_storage_account.test.name

  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics"]
}
`},
			GoodExample: []string{`
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
    bypass                     = ["Metrics", "AzureServices"]
  }

  tags = {
    environment = "staging"
  }
}

resource "azurerm_storage_account_network_rules" "test" {
  resource_group_name  = azurerm_resource_group.test.name
  storage_account_name = azurerm_storage_account.test.name

  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.test.id]
  bypass                     = ["Metrics", "AzureServices"]
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#bypass",
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#bypass",
				"https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account_network_rules", "azurerm_storage_account"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			blockName := resourceBlock.FullName()

			if resourceBlock.IsResourceType("azurerm_storage_account") {
				if resourceBlock.MissingChild("network_rules") {
					return
				}
				resourceBlock = resourceBlock.GetBlock("network_rules")

			}

			if resourceBlock.HasChild("bypass") {
				bypass := resourceBlock.GetAttribute("bypass")
				if bypass.IsNotNil() && !bypass.Contains("AzureServices") {
					set.AddResult().
						WithDescription("Resource '%s' defines a network rule that doesn't allow bypass of Microsoft Services.", blockName)
				}
			}

		},
	})
}
