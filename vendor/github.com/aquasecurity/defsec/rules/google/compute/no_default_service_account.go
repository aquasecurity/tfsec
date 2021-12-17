package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoDefaultServiceAccount = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-default-service-account",
		Summary:     "Instances should not use the default service account",
		Impact:      "Instance has full access to the project",
		Resolution:  "Remove use of default service account",
		Explanation: `The default service account has full project access. Instances should instead be assigned the minimal access they need.`,
		Links:       []string{},
		Severity:    severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.ServiceAccount.Email.IsEmpty() || instance.ServiceAccount.Email.EndsWith("-compute@developer.gserviceaccount.com") {
				results.Add(
					"Instance uses the default service account.",
					instance.ServiceAccount.Email,
				)
			}
		}
		return
	},
)
