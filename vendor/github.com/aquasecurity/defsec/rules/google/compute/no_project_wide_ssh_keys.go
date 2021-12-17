package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoProjectWideSshKeys = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0030",
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-project-wide-ssh-keys",
		Summary:     "Disable project-wide SSH keys for all instances",
		Impact:      "Compromise of a single key pair compromises all instances",
		Resolution:  "Disable project-wide SSH keys",
		Explanation: `Use of project-wide SSH keys means that a compromise of any one of these key pairs can result in all instances being compromised. It is recommended to use instance-level keys.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.EnableProjectSSHKeyBlocking.IsFalse() {
				results.Add(
					"Instance allows use of project-level SSH keys.",
					instance.EnableProjectSSHKeyBlocking,
				)
			}
		}
		return
	},
)
