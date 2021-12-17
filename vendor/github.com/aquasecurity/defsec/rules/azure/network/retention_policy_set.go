package network

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRetentionPolicySet = rules.Register(
	rules.Rule{
		Provider:   provider.AzureProvider,
		Service:    "network",
		ShortCode:  "retention-policy-set",
		Summary:    "Retention policy for flow logs should be enabled and set to greater than 90 days",
		Impact:     "Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis",
		Resolution: "Ensure flow log retention is turned on with an expiry of >90 days",
		Explanation: `Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, flowLog := range s.Azure.Network.NetworkWatcherFlowLogs {
			if flowLog.RetentionPolicy.Enabled.IsFalse() {
				results.Add(
					"Flow log does not enable the log retention policy.",
					flowLog.RetentionPolicy.Enabled,
				)
			} else if flowLog.RetentionPolicy.Days.LessThan(365) {
				results.Add(
					"Flow log has a log retention policy of less than 1 year.",
					flowLog.RetentionPolicy.Days,
				)
			}
		}
		return
	},
)
