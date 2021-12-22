package platform

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoProjectLevelServiceAccountImpersonation = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0011",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-project-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the project level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of project-level, if required",
		Explanation: `Users with service account access at project level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, project := range s.Google.Platform.AllProjects() {
			for _, member := range project.Members {
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at project level.",
						member.Role,
					)
				}
			}
			for _, binding := range project.Bindings {
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at project level.",
						binding.Role,
					)
				}
			}
		}
		return
	},
)
