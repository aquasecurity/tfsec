package dynamodb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0023",
		Provider:    provider.AWSProvider,
		Service:     "dynamodb",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "DAX Cluster should always encrypt data at rest",
		Impact:      "Data can be freely read if compromised",
		Resolution:  "Enable encryption at rest for DAX Cluster",
		Explanation: `Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.DynamoDB.DAXClusters {
			if !cluster.IsManaged() {
				continue
			}
			if cluster.ServerSideEncryption.Enabled.IsFalse() {
				results.Add(
					"Cluster encryption is not enabled.",
					cluster.ServerSideEncryption.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
