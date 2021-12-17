package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseClusterLabels = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0051",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-cluster-labels",
		Summary:     "Clusters should be configured with Labels",
		Impact:      "Asset management can be limited/more difficult",
		Resolution:  "Set cluster resource labels",
		Explanation: `Labels make it easier to manage assets and differentiate between clusters and environments, allowing the mapping of computational resources to the wider organisational structure.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.ResourceLabels.Len() == 0 {
				results.Add(
					"Cluster does not use GCE resource labels.",
					cluster.ResourceLabels,
				)
			}
		}
		return
	},
)
