package elasticache

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAddDescriptionForSecurityGroup = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0049",
		Provider:   provider.AWSProvider,
		Service:    "elasticache",
		ShortCode:  "add-description-for-security-group",
		Summary:    "Missing description for security group/security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups and rules",
		Explanation: `Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, sg := range s.AWS.ElastiCache.SecurityGroups {
			if sg.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					&sg,
					sg.Description,
				)
			} else {
				results.AddPassed(&sg)
			}
		}
		return
	},
)
