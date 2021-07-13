package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AZUMinTLSForStorageAccountsSet = "AZU015"
const AZUMinTLSForStorageAccountsSetDescription = "The minimum TLS version for Storage Accounts should be TLS1_2"
const AZUMinTLSForStorageAccountsSetImpact = "The TLS version being outdated and has known vulnerabilities"
const AZUMinTLSForStorageAccountsSetResolution = "Use a more recent TLS/SSL policy for the load balancer"
const AZUMinTLSForStorageAccountsSetExplanation = `
Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.
`
const AZUMinTLSForStorageAccountsSetBadExample = `
resource "azurerm_storage_account" "bad_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
}
`
const AZUMinTLSForStorageAccountsSetGoodExample = `
resource "azurerm_storage_account" "good_example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  min_tls_version          = "TLS1_2"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUMinTLSForStorageAccountsSet,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUMinTLSForStorageAccountsSetDescription,
			Impact:      AZUMinTLSForStorageAccountsSetImpact,
			Resolution:  AZUMinTLSForStorageAccountsSetResolution,
			Explanation: AZUMinTLSForStorageAccountsSetExplanation,
			BadExample:  AZUMinTLSForStorageAccountsSetBadExample,
			GoodExample: AZUMinTLSForStorageAccountsSetGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version",
				"https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("min_tls_version") || resourceBlock.GetAttribute("min_tls_version").IsNone("TLS1_2") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have the min tls version set to TLS1_2 .", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
