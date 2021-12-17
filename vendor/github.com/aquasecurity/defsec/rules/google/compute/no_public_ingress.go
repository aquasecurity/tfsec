package compute

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngress = rules.Register(
	rules.Rule{
		Provider:   provider.GoogleProvider,
		Service:    "compute",
		ShortCode:  "no-public-ingress",
		Summary:    "An inbound firewall rule allows traffic from /0.",
		Impact:     "The port is exposed for ingress from the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.`,
		Links: []string{
			"https://cloud.google.com/vpc/docs/using-firewalls",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, network := range s.Google.Compute.Networks {
			if network.Firewall == nil {
				continue
			}
			for _, rule := range network.Firewall.IngressRules {
				if !rule.IsAllow.IsTrue() {
					continue
				}
				if rule.Enforced.IsFalse() {
					continue
				}
				for _, source := range rule.SourceRanges {
					if cidr.IsPublic(source.Value()) {
						results.Add(
							"Firewall rule allows ingress traffic from a source on the public internet.",
							source,
						)
					}
				}
			}
		}
		return
	},
)
