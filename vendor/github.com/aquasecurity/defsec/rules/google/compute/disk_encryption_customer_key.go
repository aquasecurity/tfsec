package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDiskEncryptionCustomerKey = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0034",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-customer-key",
		Summary:     "Disks should be encrypted with customer managed encryption keys",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Use managed keys to encrypt disks.",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, disk := range s.Google.Compute.Disks {
			if disk.Encryption.KMSKeyLink.IsEmpty() {
				results.Add(
					"Disk is not encrypted with a customer managed key.",
					disk.Encryption.KMSKeyLink,
				)
			}
		}
		return
	},
)
