package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNodeMetadataSecurity = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0057",
		Provider:   provider.GoogleProvider,
		Service:    "gke",
		ShortCode:  "node-metadata-security",
		Summary:    "Node metadata value disables metadata concealment.",
		Impact:     "Metadata that isn't concealed potentially risks leakage of sensitive data",
		Resolution: "Set node metadata to SECURE or GKE_METADATA_SERVER",
		Explanation: `If the <code>workload_metadata_config</code> block within <code>node_config</code> is included, the <code>node_metadata</code> attribute should be configured securely.

The attribute should be set to <code>SECURE</code> to use metadata concealment, or <code>GKE_METADATA_SERVER</code> if workload identity is enabled. This ensures that the VM metadata is not unnecessarily exposed to pods.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			metadata := cluster.NodeConfig.WorkloadMetadataConfig.NodeMetadata
			if metadata.EqualTo("UNSPECIFIED") || metadata.EqualTo("EXPOSE") {
				results.Add(
					"Cluster exposes node metadata of pools by default.",
					metadata,
				)
			}
			for _, pool := range cluster.NodePools {
				metadata := pool.NodeConfig.WorkloadMetadataConfig.NodeMetadata
				if metadata.EqualTo("UNSPECIFIED") || metadata.EqualTo("EXPOSE") {
					results.Add(
						"Node pool exposes node metadata.",
						metadata,
					)
				}
			}
		}
		return
	},
)
