package compute

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.OpenStackProvider,
		Service:     "compute",
		ShortCode:   "no-public-access",
		Summary:     "A firewall rule allows traffic from/to the public internet",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive firewall rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, rule := range s.OpenStack.Compute.Firewall.AllowRules {
			if rule.Enabled.IsFalse() {
				continue
			}
			if rule.Destination.IsEmpty() {
				results.Add(
					"Firewall rule does not restrict destination address internally.",
					rule.Destination,
				)
			} else if cidr.IsPublic(rule.Destination.Value()) {
				results.Add(
					"Firewall rule allows public egress.",
					rule.Destination,
				)
			}
			if rule.Source.IsEmpty() {
				results.Add(
					"Firewall rule does not restrict source address internally.",
					rule.Source,
				)
			} else if cidr.IsPublic(rule.Source.Value()) {
				results.Add(
					"Firewall rule allows public ingress.",
					rule.Source,
				)
			}

		}
		return
	},
)
