package database

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSecureTlsPolicy = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0026",
		Provider:    provider.AzureProvider,
		Service:     "database",
		ShortCode:   "secure-tls-policy",
		Summary:     "Databases should have the minimum TLS set for connections",
		Impact:      "Outdated TLS policies increase exposure to known issues",
		Resolution:  "Use the most modern TLS policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			}
		}
		return
	},
)
