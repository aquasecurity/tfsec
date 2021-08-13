package keyvault

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
		LegacyID:  "AZU020",
		Service:   "keyvault",
		ShortCode: "specify-network-acl",
		Documentation: rule.RuleDocumentation{
			Summary:    "Key vault should have the network acl block specified",
			Impact:     "Without a network ACL the key vault is freely accessible",
			Resolution: "Set a network ACL for the key vault",
			Explanation: `
Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. 

The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.
`,
			BadExample: []string{`
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false
}
`},
			GoodExample: []string{`
resource "azurerm_key_vault" "good_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.good_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false

    network_acls {
        bypass = "AzureServices"
        default_action = "Deny"
    }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls",
				"https://docs.microsoft.com/en-us/azure/key-vault/general/network-security",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_key_vault"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			defaultActionAttr := resourceBlock.GetNestedAttribute("network_acls.default_action")
			if defaultActionAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' specifies does not specify a network acl block with default action.", resourceBlock.FullName())
				return
			}

			if !defaultActionAttr.Equals("Deny") {
				set.AddResult().
					WithDescription("Resource '%s' specifies does not specify a network acl block.", resourceBlock.FullName()).
					WithAttribute(defaultActionAttr)
			}

		},
	})
}
