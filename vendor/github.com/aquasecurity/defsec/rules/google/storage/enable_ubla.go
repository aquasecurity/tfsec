package storage

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableUbla = rules.Register(
	rules.Rule{
                AVDID: "AVD-GCP-0002",
		Provider:    provider.GoogleProvider,
		Service:     "storage",
		ShortCode:   "enable-ubla",
		Summary:     "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
		Impact:      "ACLs are difficult to manage and often lead to incorrect/unintended configurations.",
		Resolution:  "Enable uniform bucket level access to provide a uniform permissioning system.",
		Explanation: `When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs.`,
		Links: []string{
			"https://cloud.google.com/storage/docs/uniform-bucket-level-access",
			"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.Google.Storage.Buckets {
			if bucket.EnableUniformBucketLevelAccess.IsFalse() {
				results.Add(
					"Bucket has uniform bucket level access disabled.",
					bucket.EnableUniformBucketLevelAccess,
				)
			}
		}
		return
	},
)
