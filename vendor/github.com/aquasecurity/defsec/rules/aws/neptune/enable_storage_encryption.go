package neptune

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStorageEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0076",
		Provider:    provider.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-storage-encryption",
		Summary:     "Neptune storage must be encrypted at rest",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of Neptune storage",
		Explanation: `Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					&cluster,
					cluster.StorageEncrypted,
				)
			} else if cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not encrypt data with a customer managed key.",
					&cluster,
					cluster.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
