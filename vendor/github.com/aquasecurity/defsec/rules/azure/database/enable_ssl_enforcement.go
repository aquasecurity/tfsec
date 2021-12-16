package database

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableSslEnforcement = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0020",
		Provider:    provider.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-ssl-enforcement",
		Summary:     "SSL should be enforced on database connections where applicable",
		Impact:      "Insecure connections could lead to data loss and other vulnerabilities",
		Resolution:  "Enable SSL enforcement",
		Explanation: `SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			}
		}
		return
	},
)
