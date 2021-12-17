package documentdb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableStorageEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0021",
		Provider:    provider.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-storage-encryption",
		Summary:     "DocumentDB storage must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable storage encryption",
		Explanation: `Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.`,
		Links:       []string{"https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html"},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster storage does not have encryption enabled.",
					&cluster,
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
