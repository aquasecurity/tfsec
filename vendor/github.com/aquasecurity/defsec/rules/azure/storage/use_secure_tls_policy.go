package storage

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0011",
		Provider:   provider.AzureProvider,
		Service:    "storage",
		ShortCode:  "use-secure-tls-policy",
		Summary:    "The minimum TLS version for Storage Accounts should be TLS1_2",
		Impact:     "The TLS version being outdated and has known vulnerabilities",
		Resolution: "Use a more recent TLS/SSL policy for the load balancer",
		Explanation: `Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			if account.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Storage account uses an insecure TLS version.",
					account.MinimumTLSVersion,
				)
			}
		}
		return
	},
)
