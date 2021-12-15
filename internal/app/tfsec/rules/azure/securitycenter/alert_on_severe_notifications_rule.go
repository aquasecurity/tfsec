package securitycenter

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.`,
		BadExample: []string{`
		resource "azurerm_security_center_contact" "bad_example" {
		email = "bad_example@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = false
		alerts_to_admins = false
		}
		`},
		GoodExample: []string{`
		resource "azurerm_security_center_contact" "good_example" {
		email = "good_example@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = true
		alerts_to_admins = true
		}
	`},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications",
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"azurerm_security_center_contact"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("alert_notifications") {
				results.Add("Resource is missing the required setting for alert_notifications", resourceBlock)
				return
			}

			alertNotificationsAttr := resourceBlock.GetAttribute("alert_notifications")
			if alertNotificationsAttr.IsFalse() {
				results.Add("Resource has alert_notifications turned off", alertNotificationsAttr)
			}

			return results
		},
	})
}
