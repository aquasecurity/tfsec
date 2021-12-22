package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforcePodSecurityPolicy = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0047",
		Provider:   provider.GoogleProvider,
		Service:    "gke",
		ShortCode:  "enforce-pod-security-policy",
		Summary:    "Pod security policy enforcement not defined.",
		Impact:     "Pods could be operating with more permissions than required to be effective",
		Resolution: "Use security policies for pods to restrict permissions to those needed to be effective",
		Explanation: `By default, Pods in Kubernetes can operate with capabilities beyond what they require. You should constrain the Pod's capabilities to only those required for that workload.

Kubernetes offers controls for restricting your Pods to execute with only explicitly granted capabilities. 

Pod Security Policy allows you to set smart defaults for your Pods, and enforce controls you want to enable across your fleet. 

The policies you define should be specific to the needs of your application`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.PodSecurityPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster pod security policy is not enforced.",
					cluster.PodSecurityPolicy.Enabled,
				)
			}
		}
		return
	},
)
