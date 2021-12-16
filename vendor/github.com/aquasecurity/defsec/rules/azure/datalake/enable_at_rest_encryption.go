package datalake

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "datalake",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Unencrypted data lake storage.",
		Impact:      "Data could be read if compromised",
		Resolution:  "Enable encryption of data lake storage",
		Explanation: `Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, store := range s.Azure.DataLake.Stores {
			if store.EnableEncryption.IsFalse() {
				results.Add(
					"Data lake store is not encrypted.",
					store.EnableEncryption,
				)
			}
		}
		return
	},
)
