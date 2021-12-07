package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPlaintextVmDiskKeys = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-plaintext-vm-disk-keys",
		Summary:     "VM disk encryption keys should not be provided in plaintext",
		Impact:      "Compromise of encryption keys",
		Resolution:  "Use managed keys or provide the raw key via a secrets manager ",
		Explanation: `Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, disk := range append(instance.BootDisks, instance.AttachedDisks...) {
				if disk.Encryption.RawKey.Len() > 0 {
					results.Add(
						"Instance disk has encryption key provided in plaintext.",
						disk.Encryption.RawKey,
					)
				}
			}
		}
		return
	},
)
