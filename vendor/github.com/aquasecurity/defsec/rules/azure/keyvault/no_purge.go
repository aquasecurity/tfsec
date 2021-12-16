package keyvault

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPurge = rules.Register(
	rules.Rule{
                AVDID: "AVD-AZU-0016",
		Provider:   provider.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "no-purge",
		Summary:    "Key vault should have purge protection enabled",
		Impact:     "Keys could be purged from the vault without protection",
		Resolution: "Enable purge protection for key vaults",
		Explanation: `Purge protection is an optional Key Vault behavior and is not enabled by default.

Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			if vault.EnablePurgeProtection.IsFalse() {
				results.Add(
					"Vault does not have purge protection enabled.",
					vault.EnablePurgeProtection,
				)
			}
		}
		return
	},
)
