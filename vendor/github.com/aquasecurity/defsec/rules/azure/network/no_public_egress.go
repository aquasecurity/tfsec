package network

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgress = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0051",
		Provider:   provider.AzureProvider,
		Service:    "network",
		ShortCode:  "no-public-egress",
		Summary:    "An outbound network security rule allows traffic to /0.",
		Impact:     "The port is exposed for egress to the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.Azure.Network.SecurityGroups {
			for _, rule := range group.OutboundAllowRules {
				for _, ip := range rule.DestinationAddresses {
					if cidr.IsPublic(ip.Value()) {
						results.Add(
							"Security group rule allows egress to public internet.",
							ip,
						)
					}
				}
			}
		}
		return
	},
)
