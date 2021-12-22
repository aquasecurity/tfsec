package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngress = rules.Register(
	rules.Rule{
                AVDID: "AVD-DIG-0001",
		Provider:    provider.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "no-public-ingress",
		Summary:     "The firewall has an inbound rule with open access",
		Impact:      "Your port is exposed to the internet",
		Resolution:  "Set a more restrictive CIRDR range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
				)
			}
		}
		return
	},
)
