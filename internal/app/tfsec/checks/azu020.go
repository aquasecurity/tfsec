package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultNetworkAcl scanner.RuleCode = "AZU020"
const AZUKeyVaultNetworkAclDescription scanner.RuleSummary = "Key vault should have the network acl block specified"
const AZUKeyVaultNetworkAclExplanation = `
Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. 

The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.
`
const AZUKeyVaultNetworkAclBadExample = `
resource "azurerm_key_vault" "bad_example" {
    name                        = "examplekeyvault"
    location                    = azurerm_resource_group.bad_example.location
    enabled_for_disk_encryption = true
    soft_delete_retention_days  = 7
    purge_protection_enabled    = false
}
`
const AZUKeyVaultNetworkAclGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AZUKeyVaultNetworkAcl,
		Documentation: scanner.CheckDocumentation{
			Summary:     AZUKeyVaultNetworkAclDescription,
			Explanation: AZUKeyVaultNetworkAclExplanation,
			BadExample:  AZUKeyVaultNetworkAclBadExample,
			GoodExample: AZUKeyVaultNetworkAclGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls",
				"https://docs.microsoft.com/en-us/azure/key-vault/general/network-security",
			},
		},
		Provider:       scanner.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("network_acls") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			networkAcls := block.GetBlock("network_acls")
			if networkAcls == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if networkAcls.MissingChild("default_action"){
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' specifies does not specify a default action in the network acl.", block.FullName()),
						networkAcls.Range(),
						scanner.SeverityError,
					),
				}
			}

			defaultAction := networkAcls.GetAttribute("default_action")
			if !defaultAction.Equals("Deny") {
				return []scanner.Result {
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName()),
						defaultAction.Range(),
						defaultAction,
						scanner.SeverityError,
						),
				}
			}


			return nil
		},
	})
}
