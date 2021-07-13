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
	"github.com/zclconf/go-cty/cty"
)

const AZUStorageAccountHTTPSenabled = "AZU010"
const AZUStorageAccountHTTPSenabledDescription = "Ensure HTTPS is enabled on Azure Storage Account"
const AZUStorageAccountHTTPSenabledImpact = "HTTP access to storage account could be read if intercepted"
const AZUStorageAccountHTTPSenabledResolution = "Only use HTTPS for storage account"
const AZUStorageAccountHTTPSenabledExplanation = `
Requiring HTTPS in Storage Account helps to minimize the risk of eavesdropping.
`
const AZUStorageAccountHTTPSenabledBadExample = `
resource "azurerm_storage_account" "bad_example" {
	enable_https_traffic_only = false
}
`
const AZUStorageAccountHTTPSenabledGoodExample = `
resource "azurerm_storage_account" "good_example" {
	enable_https_traffic_only = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AZUStorageAccountHTTPSenabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AZUStorageAccountHTTPSenabledDescription,
			Impact:      AZUStorageAccountHTTPSenabledImpact,
			Resolution:  AZUStorageAccountHTTPSenabledResolution,
			Explanation: AZUStorageAccountHTTPSenabledExplanation,
			BadExample:  AZUStorageAccountHTTPSenabledBadExample,
			GoodExample: AZUStorageAccountHTTPSenabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account",
				"https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_storage_account", "enable_https_traffic_only"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			enabledAttr := resourceBlock.GetAttribute("enable_https_traffic_only")
			if enabledAttr != nil && enabledAttr.Type() == cty.Bool && enabledAttr.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf(
							"Resource '%s' enable_https_traffic_only disabled.",
							resourceBlock.FullName(),
						)).
						WithRange(enabledAttr.Range()).
						WithAttributeAnnotation(enabledAttr),
				)
			}

		},
	})
}
