package securitycenter

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSetRequiredContactDetails = rules.Register(
	rules.Rule{
		Provider:   provider.AzureProvider,
		Service:    "security-center",
		ShortCode:  "set-required-contact-details",
		Summary:    "The required contact details should be set for security center",
		Impact:     "Without a telephone number set, Azure support can't contact",
		Resolution: "Set a telephone number for security center contact",
		Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.`,
		Links: []string{
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, contact := range s.Azure.SecurityCenter.Contacts {
			if contact.Phone.IsEmpty() {
				results.Add(
					"Security contact does not have a phone number listed.",
					contact.Phone,
				)
			}
		}
		return
	},
)
