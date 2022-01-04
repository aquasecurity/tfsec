package platform

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoFolderLevelServiceAccountImpersonation = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0005",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-folder-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the folder level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of folder-level, if required",
		Explanation: `Users with service account access at folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, folder := range s.Google.Platform.AllFolders() {
			for _, member := range folder.Members {
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at folder level.",
						member.Role,
					)
				}
			}
			for _, binding := range folder.Bindings {
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at folder level.",
						binding.Role,
					)
				}
			}
		}
		return
	},
)
