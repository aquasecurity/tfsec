package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStackdriverLogging = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0060",
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-stackdriver-logging",
		Summary:     "Stackdriver Logging should be enabled",
		Impact:      "Visibility will be reduced",
		Resolution:  "Enable StackDriver logging",
		Explanation: `StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for moitoring, debugging, etc.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.LoggingService.NotEqualTo("logging.googleapis.com/kubernetes") {
				results.Add(
					"Cluster does not use the logging.googleapis.com/kubernetes StackDriver logging service.",
					cluster.LoggingService,
				)
			}
		}
		return
	},
)
