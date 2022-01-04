package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPgLogConnections = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0016",
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-connections",
		Summary:     "Ensure that logging of connections is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable connection logging.",
		Explanation: `Logging connections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CONNECTIONS",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogConnections.IsFalse() {
				results.Add(
					"Database instance is not configured to log connections.",
					instance.Settings.Flags.LogConnections,
				)
			}
		}
		return
	},
)
