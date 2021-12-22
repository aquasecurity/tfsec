package vpc

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgressSgr = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0104",
		Provider:    provider.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-public-egress-sgr",
		Summary:     "An egress security group rule allows traffic to /0.",
		Impact:      "Your port is egressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.AWS.VPC.SecurityGroups {
			for _, rule := range group.EgressRules {
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) {
						fail = true
						results.Add(
							"Security group rule allows egress to public internet.",
							&group,
							block,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
