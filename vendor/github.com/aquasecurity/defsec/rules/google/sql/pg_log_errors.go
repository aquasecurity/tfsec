package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgLogErrors = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0018",
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-errors",
		Summary:     "Ensure that Postgres errors are logged",
		Impact:      "Loss of error logging",
		Resolution:  "Set the minimum log severity to at least ERROR",
		Explanation: `Setting the minimum log severity too high will cause errors not to be logged`,
		Links: []string{
			"https://postgresqlco.nf/doc/en/param/log_min_messages/",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogMinMessages.IsOneOf("FATAL", "PANIC", "LOG") {
				results.Add(
					"Database instance is not configured to log errors.",
					instance.Settings.Flags.LogMinMessages,
				)
			}
		}
		return
	},
)
