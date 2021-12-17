package database

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPostgresConfigurationLogCheckpoints = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0024",
		Provider:    provider.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-log-checkpoints",
		Summary:     "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No error and query logs generated on checkpoint",
		Resolution:  "Enable checkpoint logging",
		Explanation: `Postgresql can generate logs for checkpoints to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Config.LogCheckpoints.IsFalse() {
				results.Add(
					"Database server is not configured to log checkpoints.",
					server.Config.LogCheckpoints,
				)
			}
		}
		return
	},
)
