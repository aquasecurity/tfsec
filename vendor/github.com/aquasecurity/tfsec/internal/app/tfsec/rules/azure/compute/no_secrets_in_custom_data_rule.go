package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/rules/azure/compute"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/owenrumney/squealer/pkg/squealer"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"},
		Base:           compute.CheckNoSecretsInCustomData,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("custom_data") {
				return
			}

			customDataAttr := resourceBlock.GetAttribute("custom_data")

			if resourceBlock.TypeLabel() == "azurerm_virtual_machine" {
				for _, str := range customDataAttr.ValueAsStrings() {
					if checkStringForSensitive(str) {
						results.Add("Resource has custom_data with sensitive data.", customDataAttr)
					}
				}
			} else if customDataAttr.IsResolvable() && customDataAttr.IsString() {
				encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
				if err != nil {
					debug.Log("could not decode the base64 string in the terraform, trying with the string verbatim")
					encoded = []byte(customDataAttr.Value().AsString())
				}
				if checkStringForSensitive(string(encoded)) {
					results.Add("Resource has custom_data with sensitive data.", customDataAttr)
				}

			}
			return results
		},
	})
}

func checkStringForSensitive(stringToCheck string) bool {
	return squealer.NewStringScanner().Scan(stringToCheck).TransgressionFound
}
