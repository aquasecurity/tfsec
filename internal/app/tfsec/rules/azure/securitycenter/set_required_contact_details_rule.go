package securitycenter

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

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "security-center",
		ShortCode: "set-required-contact-details",
		Documentation: rule.RuleDocumentation{
			Summary: "The required contact details should be set for security center",
			Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.`,
			Impact:     "Without a telephone number set, Azure support can't contact",
			Resolution: "Set a telephone number for security center contact",
			BadExample: `
resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_contact@example.com"
  phone = ""

  alert_notifications = true
  alerts_to_admins    = true
}
`,
			GoodExample: `
resource "azurerm_security_center_contact" "good_example" {
  email = "good_contact@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}
`,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone",
				"https://azure.microsoft.com/en-us/services/security-center/",
			},
		},
		Provider:        provider.AzureProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"azurerm_security_center_contact"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("phone") {
				set.Add(
					result.New(resourceBlock).WithDescription(fmt.Sprintf("Resource '%s' does not have a phone number set for the security contact", resourceBlock.FullName())),
				)
				return
			}

			phoneAttr := resourceBlock.GetAttribute("phone")
			if phoneAttr.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have a phone number set for the security contact", resourceBlock.FullName())).
						WithAttributeAnnotation(phoneAttr).
						WithRange(phoneAttr.Range()),
				)
			}
		},
	})
}
