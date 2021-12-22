package dns

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableDnssec = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0013",
		Provider:    provider.GoogleProvider,
		Service:     "dns",
		ShortCode:   "enable-dnssec",
		Summary:     "Cloud DNS should use DNSSEC",
		Impact:      "Unverified DNS responses could lead to man-in-the-middle attacks",
		Resolution:  "Enable DNSSEC",
		Explanation: `DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, zone := range s.Google.DNS.ManagedZones {
			if zone.DNSSec.Enabled.IsFalse() {
				results.Add(
					"Managed zone does not have DNSSEC enabled.",
					zone.DNSSec.Enabled,
				)
			}
		}
		return
	},
)
