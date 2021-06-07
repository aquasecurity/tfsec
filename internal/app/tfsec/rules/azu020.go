package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AZUKeyVaultNetworkAcl = "AZU020"
const AZUKeyVaultNetworkAclDescription = "Key vault should have the network acl block specified"
const AZUKeyVaultNetworkAclImpact = "Without a network ACL the key vault is freely accessible"
const AZUKeyVaultNetworkAclResolution = "Set a network ACL for the key vault"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUKeyVaultNetworkAcl,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUKeyVaultNetworkAclDescription,
			Impact:      AZUKeyVaultNetworkAclImpact,
			Resolution:  AZUKeyVaultNetworkAclResolution,
			Explanation: AZUKeyVaultNetworkAclExplanation,
			BadExample:  AZUKeyVaultNetworkAclBadExample,
			GoodExample: AZUKeyVaultNetworkAclGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls",
				"https://docs.microsoft.com/en-us/azure/key-vault/general/network-security",
			},
		},
		Provider:       provider.AzureProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_key_vault"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			if block.MissingChild("network_acls") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName())).
						WithRange(block.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			networkAcls := block.GetBlock("network_acls")
			if networkAcls == nil {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName())).
						WithRange(block.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			if networkAcls.MissingChild("default_action") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' specifies does not specify a default action in the network acl.", block.FullName())).
						WithRange(networkAcls.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			defaultActionAttr := networkAcls.GetAttribute("default_action")
			if !defaultActionAttr.Equals("Deny") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' specifies does not specify a network acl block.", block.FullName())).
						WithRange(defaultActionAttr.Range()).
						WithAttributeAnnotation(defaultActionAttr).
						WithSeverity(severity.Error),
				)
			}

		},
	})
}
