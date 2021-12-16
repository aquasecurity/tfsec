package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0039",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "SSL policies should enforce secure versions of TLS",
		Impact:      "Data in transit is not sufficiently secured",
		Resolution:  "Enforce a minimum TLS version of 1.2",
		Explanation: `TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.`,
		Links:       []string{},
		Severity:    severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, policy := range s.Google.Compute.SSLPolicies {
			if policy.MinimumTLSVersion.NotEqualTo("TLS_1_2") {
				results.Add(
					"TLS policy does not specify a minimum of TLS 1.2",
					policy.MinimumTLSVersion,
				)
			}
		}
		return
	},
)
