package datalake

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
		LegacyID:  "AZU004",
		Service:   "datalake",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted data lake storage.",
			Impact:     "Data could be read if compromised",
			Resolution: "Enable encryption of data lake storage",
			Explanation: `
Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.
`,
			BadExample: []string{`
resource "azurerm_data_lake_store" "bad_example" {
	encryption_state = "Disabled"
}`},
			GoodExample: []string{`
resource "azurerm_data_lake_store" "good_example" {
	encryption_state = "Enabled"
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_lake_store",
				"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_data_lake_store"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("encryption_state") {
				return
			}

			encryptionStateAttr := resourceBlock.GetAttribute("encryption_state")
			if encryptionStateAttr.Equals("Disabled") {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted data lake store.", resourceBlock.FullName()).WithAttribute(encryptionStateAttr)
			}

		},
	})
}
