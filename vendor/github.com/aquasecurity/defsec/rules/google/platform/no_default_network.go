package platform

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoDefaultNetwork = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0010",
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-default-network",
		Summary:     "Default network should not be created at project level",
		Impact:      "Exposure of internal infrastructure/services to public internet",
		Resolution:  "Disable automatic default network creation",
		Explanation: `The default network which is provided for a project contains multiple insecure firewall rules which allow ingress to the project's infrastructure. Creation of this network should therefore be disabled.`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, project := range s.Google.Platform.AllProjects() {
			if project.AutoCreateNetwork.IsTrue() {
				results.Add(
					"Project has automatic network creation enabled.",
					project.AutoCreateNetwork,
				)
			}
		}
		return
	},
)
