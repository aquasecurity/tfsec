package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableNetworkPolicy = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0056",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-network-policy",
		Summary:     "Network Policy should be enabled on GKE clusters",
		Impact:      "Unrestricted inter-cluster communication",
		Resolution:  "Enable network policy",
		Explanation: `Enabling a network policy allows the segregation of network traffic by namespace`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.NetworkPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have a network policy enabled.",
					cluster.NetworkPolicy.Enabled,
				)
			}
		}
		return
	},
)
