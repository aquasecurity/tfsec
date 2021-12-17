package securitycenter

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/azure/securitycenter"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStandardSubscription = rules.Register(
	rules.Rule{
		Provider:   provider.AzureProvider,
		Service:    "security-center",
		ShortCode:  "enable-standard-subscription",
		Summary:    "Enable the standard security center subscription tier",
		Impact:     "Using free subscription does not enable Azure Defender for the resource type",
		Resolution: "Enable standard subscription tier to benefit from Azure Defender",
		Explanation: `To benefit from Azure Defender you should use the Standard subscription tier.
			
			Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, sub := range s.Azure.SecurityCenter.Subscriptions {
			if sub.Tier.EqualTo(securitycenter.TierFree) {
				results.Add(
					"Security center subscription uses the free tier.",
					sub.Tier,
				)
			}
		}
		return
	},
)
