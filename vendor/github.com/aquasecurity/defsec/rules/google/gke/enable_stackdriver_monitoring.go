package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStackdriverMonitoring = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0052",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-stackdriver-monitoring",
		Summary:     "Stackdriver Monitoring should be enabled",
		Impact:      "Visibility will be reduced",
		Resolution:  "Enable StackDriver monitoring",
		Explanation: `StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.MonitoringService.NotEqualTo("monitoring.googleapis.com/kubernetes") {
				results.Add(
					"Cluster does not use the monitoring.googleapis.com/kubernetes StackDriver monitoring service.",
					cluster.MonitoringService,
				)
			}
		}
		return
	},
)
