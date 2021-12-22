package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoLegacyAuthentication = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0064",
		Provider:   provider.GoogleProvider,
		Service:    "gke",
		ShortCode:  "no-legacy-authentication",
		Summary:    "Legacy client authentication methods utilized.",
		Impact:     "Username/password or certificate authentication methods are less secure",
		Resolution: "Use service account or OAuth for authentication",
		Explanation: `It is recommended to use Service Accounts and OAuth as authentication methods for accessing the master in the container cluster. 

Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.MasterAuth.ClientCertificate.IssueCertificate.IsTrue() {
				results.Add(
					"Cluster allows the use of certificates for master authentication.",
					cluster.MasterAuth.ClientCertificate.IssueCertificate,
				)
			}
			if cluster.MasterAuth.Username.NotEqualTo("") {
				results.Add(
					"Cluster allows the use of basic auth for master authentication.",
					cluster.MasterAuth.Username,
				)
			}
		}
		return
	},
)
