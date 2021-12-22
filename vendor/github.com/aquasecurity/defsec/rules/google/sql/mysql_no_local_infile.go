package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckMysqlNoLocalInfile = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0026",
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "mysql-no-local-infile",
		Summary:     "Disable local_infile setting in MySQL",
		Impact:      "Arbitrary files read by attackers when combined with a SQL injection vulnerability.",
		Resolution:  "Disable the local infile setting",
		Explanation: `Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.`,
		Links: []string{
			"https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.DatabaseFamily() != sql.DatabaseFamilyMySQL {
				continue
			}
			if instance.Settings.Flags.LocalInFile.IsTrue() {
				results.Add(
					"Database instance has local file read access enabled.",
					instance.Settings.Flags.LocalInFile,
				)
			}
		}
		return
	},
)
