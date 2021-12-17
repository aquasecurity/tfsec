package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseServiceAccount = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0050",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-service-account",
		Summary:     "Checks for service account defined for GKE nodes",
		Impact:      "Service accounts with wide permissions can increase the risk of compromise",
		Resolution:  "Use limited permissions for service accounts to be effective",
		Explanation: `You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.RemoveDefaultNodePool.IsFalse() {
				if cluster.NodeConfig.ServiceAccount.IsEmpty() {
					results.Add(
						"Cluster does not override the default service account.",
						cluster.NodeConfig.ServiceAccount,
					)
				}
			}
			for _, pool := range cluster.NodePools {
				if pool.NodeConfig.ServiceAccount.IsEmpty() {
					results.Add(
						"Node pool does not override the default service account.",
						pool.NodeConfig.ServiceAccount,
					)
				}

			}
		}
		return
	},
)
