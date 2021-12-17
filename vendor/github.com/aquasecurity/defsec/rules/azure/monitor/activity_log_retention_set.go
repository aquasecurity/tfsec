package monitor

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckActivityLogRetentionSet = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "monitor",
		ShortCode:   "activity-log-retention-set",
		Summary:     "Ensure the activity retention log is set to at least a year",
		Impact:      "Short life activity logs can lead to missing records when investigating a breach",
		Resolution:  "Set a retention period that will allow for delayed investigation",
		Explanation: `The average time to detect a breach is up to 210 days, to ensure that all the information required for an effective investigation is available, the retention period should allow for delayed starts to investigating.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, profile := range s.Azure.Monitor.LogProfiles {
			if profile.RetentionPolicy.Enabled.IsFalse() {
				results.Add(
					"Profile does not enable the log retention policy.",
					profile.RetentionPolicy.Enabled,
				)
			} else if profile.RetentionPolicy.Days.LessThan(365) {
				results.Add(
					"Profile has a log retention policy of less than 1 year.",
					profile.RetentionPolicy.Days,
				)
			}
		}
		return
	},
)
