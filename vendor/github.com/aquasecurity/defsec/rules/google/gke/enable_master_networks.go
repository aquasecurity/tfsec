package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableMasterNetworks = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0061",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-master-networks",
		Summary:     "Master authorized networks should be configured on GKE clusters",
		Impact:      "Unrestricted network access to the master",
		Resolution:  "Enable master authorized networks",
		Explanation: `Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.MasterAuthorizedNetworks.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have master authorized networks enabled.",
					cluster.MasterAuthorizedNetworks.Enabled,
				)
			}
		}
		return
	},
)
