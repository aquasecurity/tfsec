package vpc

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0107",
		Provider:    provider.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-public-ingress-sgr",
		Summary:     "An ingress security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.AWS.VPC.SecurityGroups {
			for _, rule := range group.IngressRules {
				var failed bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) {
						failed = true
						results.Add(
							"Security group rule allows ingress from public internet.",
							&group,
							block,
						)
					}
				}
				if !failed {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
