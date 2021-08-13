package securitycenter

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
		Service:   "security-center",
		ShortCode: "alert-on-severe-notifications",
		Documentation: rule.RuleDocumentation{
			Summary: "Send notification emails for high severity alerts",
			Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.`,
			Impact:     "The ability to react to high severity notifications could be delayed",
			Resolution: " Set alert notifications to be on",
			BadExample: []string{`
resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_example@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = false
  alerts_to_admins    = false
}
			`},
			GoodExample: []string{`
resource "azurerm_security_center_contact" "good_example" {
  email = "good_example@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}
			`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#alert_notifications",
				"https://azure.microsoft.com/en-us/services/security-center/",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_security_center_contact"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("alert_notifications") {
				set.AddResult().
					WithDescription("Resource '%s' is missing the required setting for alert_notifications", resourceBlock.FullName())

				return
			}

			alertNotificationsAttr := resourceBlock.GetAttribute("alert_notifications")
			if alertNotificationsAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has alert_notifications turned off", resourceBlock.FullName()).
					WithAttribute(alertNotificationsAttr)
			}

		},
	})
}
