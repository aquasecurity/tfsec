package securitycenter

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.`,
		BadExample: []string{`
		resource "azurerm_security_center_contact" "bad_example" {
		email = "bad_contact@example.com"
		phone = ""

		alert_notifications = true
		alerts_to_admins = true
		}
		`},
		GoodExample: []string{`
		resource "azurerm_security_center_contact" "good_example" {
		email = "good_contact@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = true
		alerts_to_admins = true
		}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone",
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_security_center_contact"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("phone") {
				results.Add("Resource does not have a phone number set for the security contact", resourceBlock)
				return
			}

			phoneAttr := resourceBlock.GetAttribute("phone")
			if phoneAttr.IsEmpty() {
				results.Add("Resource does not have a phone number set for the security contact", phoneAttr)
			}
			return results
		},
	})
}
