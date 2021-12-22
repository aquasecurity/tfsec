package platform

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPrivilegedServiceAccounts = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0007",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-privileged-service-accounts",
		Summary:     "Service accounts should not have roles assigned with excessive privileges",
		Impact:      "Cloud account takeover if a resource using a service account is compromised",
		Resolution:  "Limit service account access to minimal required set",
		Explanation: `Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/understanding-roles",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, project := range s.Google.Platform.AllProjects() {
			for _, member := range project.Members {
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					}
				}
			}
			for _, binding := range project.Bindings {
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						}
					}
				}
			}
		}
		for _, folder := range s.Google.Platform.AllFolders() {
			for _, member := range folder.Members {
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					}
				}
			}
			for _, binding := range folder.Bindings {
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						}
					}
				}
			}

		}

		for _, org := range s.Google.Platform.Organizations {
			for _, member := range org.Members {
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					}
				}
			}
			for _, binding := range org.Bindings {
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						}
					}
				}
			}

		}

		return
	},
)

func isRolePrivileged(role string) bool {
	switch {
	case role == "roles/owner":
		return true
	case role == "roles/editor":
		return true
	case strings.HasSuffix(strings.ToLower(role), "admin"):
		return true
	}
	return false
}
