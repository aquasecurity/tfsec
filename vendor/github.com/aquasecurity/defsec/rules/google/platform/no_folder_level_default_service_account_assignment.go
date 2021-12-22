package platform

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoFolderLevelDefaultServiceAccountAssignment = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0004",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-folder-level-default-service-account-assignment",
		Summary:     "Roles should not be assigned to default service accounts",
		Impact:      "Violation of principal of least privilege",
		Resolution:  "Use specialised service accounts for specific purposes.",
		Explanation: `Deault service accounts should not be used - consider creating specialised service accounts for individual purposes.`,
		Links: []string{
			"",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, folder := range s.Google.Platform.AllFolders() {
			for _, member := range folder.Members {
				if isMemberDefaultServiceAccount(member.Member.Value()) {
					results.Add(
						"Role is assigned to a default service account at folder level.",
						member.Member,
					)
				}
			}
			for _, binding := range folder.Bindings {
				for _, member := range binding.Members {
					if isMemberDefaultServiceAccount(member.Value()) {
						results.Add(
							"Role is assigned to a default service account at folder level.",
							member,
						)
					}
				}
			}

		}
		return
	},
)

func isMemberDefaultServiceAccount(member string) bool {
	return strings.HasSuffix(member, "-compute@developer.gserviceaccount.com") || strings.HasSuffix(member, "@appspot.gserviceaccount.com")
}
