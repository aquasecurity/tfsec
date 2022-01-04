package efs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0037",
		Provider:    provider.AWSProvider,
		Service:     "efs",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "EFS Encryption has not been enabled",
		Impact:      "Data can be read from the EFS if compromised",
		Resolution:  "Enable encryption for EFS",
		Explanation: `If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.`,
		Links: []string{
			"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, fs := range s.AWS.EFS.FileSystems {
			if fs.Encrypted.IsFalse() {
				results.Add(
					"File system is not encrypted.",
					&fs,
					fs.Encrypted,
				)
			} else {
				results.AddPassed(&fs)
			}
		}
		return
	},
)
