package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoOrgLevelDefaultServiceAccountAssignment = rules.Register(
	rules.Rule{
		AVDID:       "AVD-GCP-0008",
		Provider:    provider.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-org-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Default service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoOrgLevelDefaultServiceAccountAssignmentGoodExamples,
			BadExamples:         terraformNoOrgLevelDefaultServiceAccountAssignmentBadExamples,
			Links:               terraformNoOrgLevelDefaultServiceAccountAssignmentLinks,
			RemediationMarkdown: terraformNoOrgLevelDefaultServiceAccountAssignmentRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, org := range s.Google.IAM.Organizations {
			for _, binding := range org.Bindings {
				if binding.IncludesDefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						binding.IncludesDefaultServiceAccount,
					)
				} else {
					for _, member := range binding.Members {
						if isMemberDefaultServiceAccount(member.Value()) {
							results.Add(
								"Role is assigned to a default service account at organisation level.",
								member,
							)
						}
					}
				}
			}
			for _, member := range org.Members {
				if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						member.Member,
					)
				} else if member.DefaultServiceAccount.IsTrue() {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						member.DefaultServiceAccount,
					)
				}
			}
		}
		return
	},
)
