package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableShieldedVMVTPM = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0041",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-vtpm",
		Summary:     "Instances should have Shielded VM VTPM enabled",
		Impact:      "Unable to prevent unwanted system state modification",
		Resolution:  "Enable Shielded VM VTPM",
		Explanation: `The virtual TPM provides numerous security measures to your VM.`,
		Links: []string{
			"https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.ShieldedVM.VTPMEnabled.IsFalse() {
				results.Add(
					"Instance does not have VTPM for shielded VMs enabled.",
					instance.ShieldedVM.VTPMEnabled,
				)
			}
		}
		return
	},
)
