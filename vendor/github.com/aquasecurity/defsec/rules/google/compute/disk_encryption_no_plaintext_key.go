package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDiskEncryptionRequired = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0037",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-no-plaintext-key",
		Summary:     "The encryption key used to encrypt a compute disk has been specified in plaintext.",
		Impact:      "The encryption key should be considered compromised as it is not stored securely.",
		Resolution:  "Reference a managed key rather than include the key in raw format.",
		Explanation: `Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.`,
		Links: []string{
			"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, disk := range s.Google.Compute.Disks {
			if disk.Encryption.RawKey.Len() > 0 {
				results.Add(
					"Disk encryption key is supplied in plaintext.",
					disk.Encryption.RawKey,
				)
			}
		}
		return
	},
)
