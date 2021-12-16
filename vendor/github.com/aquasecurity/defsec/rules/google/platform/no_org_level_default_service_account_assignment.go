package platform

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoOrgLevelDefaultServiceAccountAssignment = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0008",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-org-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Default service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, org := range s.Google.Platform.Organizations {
			for _, binding := range org.Bindings {
				for _, member := range binding.Members {
					if isMemberDefaultServiceAccount(member.Value()) {
						results.Add(
							"Role is assigned to a default service account at organisation level.",
							member,
						)
					}
				}
			}
			for _, member := range org.Members {
				if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at organisation level.",
						member.Member,
					)
				}
			}
		}
		return
	},
)
