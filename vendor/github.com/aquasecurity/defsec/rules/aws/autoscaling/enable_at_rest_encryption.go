package autoscaling

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0008",
		Provider:    provider.AWSProvider,
		Service:     "autoscaling",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Launch configuration with unencrypted block device.",
		Impact:      "The block device could be compromised and read from",
		Resolution:  "Turn on encryption for all block devices",
		Explanation: `Block devices should be encrypted to ensure sensitive data is held securely at rest.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, launchConfig := range s.AWS.Autoscaling.LaunchConfigurations {
			if launchConfig.RootBlockDevice != nil && launchConfig.RootBlockDevice.Encrypted.IsFalse() {
				results.Add(
					"Root block device is not encrypted.",
					&launchConfig,
					launchConfig.RootBlockDevice.Encrypted,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
			for _, device := range launchConfig.EBSBlockDevices {
				if device.Encrypted.IsFalse() {
					results.Add(
						"EBS block device is not encrypted.",
						&device,
						device.Encrypted,
					)
				} else {
					results.AddPassed(&device)
				}
			}
		}
		return
	},
)
