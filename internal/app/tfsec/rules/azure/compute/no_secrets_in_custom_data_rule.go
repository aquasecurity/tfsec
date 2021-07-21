package compute

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/owenrumney/squealer/pkg/squealer"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "compute",
		ShortCode: "no-secrets-in-custom-data",
		Documentation: rule.RuleDocumentation{
			Summary: "Ensure that no sensitive credentials are exposed in VM custom_data",
			Explanation: `	`,
			Impact:     "Sensitive credentials in custom_data can be leaked",
			Resolution: "Don't use sensitive credentials in the VM custom_data",
			BadExample: `
resource "azurerm_virtual_machine" "bad_example" {
	name = "bad_example"
	custom_data =<<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
EOF
}
`,
			GoodExample: `
resource "azurerm_virtual_machine" "bad_example" {
	name = "bad_example"
	custom_data =<<EOF
export GREETING="Hello there"
EOF
}
			`,
			Links: []string{},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_virtual_machine"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("custom_data") {
				return
			}

			customDataAttr := resourceBlock.GetAttribute("custom_data")
			for _, str := range customDataAttr.ValueAsStrings() {
				if scanResult := squealer.NewStringScanner().Scan(str); scanResult.TransgressionFound {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has custom_data with sensitive data.", resourceBlock.FullName())).
							WithRange(customDataAttr.Range()).
							WithAttributeAnnotation(customDataAttr),
					)
					return
				}
			}
		},
	})
}
