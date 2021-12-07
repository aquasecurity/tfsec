package compute

// generator-locked
import (
	"encoding/base64"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/owenrumney/squealer/pkg/squealer"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "compute",
		ShortCode: "no-secrets-in-custom-data",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure that no sensitive credentials are exposed in VM custom_data",
			Explanation: `When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.`,
			Impact:      "Sensitive credentials in custom_data can be leaked",
			Resolution:  "Don't use sensitive credentials in the VM custom_data",
			BadExample: []string{`
resource "azurerm_virtual_machine" "bad_example" {
	name = "bad_example"
	custom_data =<<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
EOF
}
`},
			GoodExample: []string{`
resource "azurerm_virtual_machine" "good_example" {
	name = "good_example"
	custom_data =<<EOF
export GREETING="Hello there"
EOF
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("custom_data") {
				return
			}

			customDataAttr := resourceBlock.GetAttribute("custom_data")

			if resourceBlock.TypeLabel() == "azurerm_virtual_machine" {
				for _, str := range customDataAttr.ValueAsStrings() {
					if checkStringForSensitive(str) {
						set.AddResult().
							WithDescription("Resource '%s' has custom_data with sensitive data.", resourceBlock.FullName()).
							WithAttribute(customDataAttr)
					}
				}
			} else if customDataAttr.IsResolvable() && customDataAttr.IsString() {
				encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
				if err != nil {
					debug.Log("could not decode the base64 string in the terraform, trying with the string verbatim")
					encoded = []byte(customDataAttr.Value().AsString())
				}
				if checkStringForSensitive(string(encoded)) {
					set.AddResult().
						WithDescription("Resource '%s' has custom_data with sensitive data.", resourceBlock.FullName()).
						WithAttribute(customDataAttr)
				}

			}
		},
	})
}

func checkStringForSensitive(stringToCheck string) bool {
	scanResult := squealer.NewStringScanner().Scan(stringToCheck)
	return scanResult.TransgressionFound
}
