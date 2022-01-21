package rds

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptClusterStorageData = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0079",
		Provider:   provider.AWSProvider,
		Service:    "rds",
		ShortCode:  "encrypt-cluster-storage-data",
		Summary:    "There is no encryption specified or encryption is disabled on the RDS Cluster.",
		Impact:     "Data can be read from the RDS cluster if it is compromised",
		Resolution: "Enable encryption for RDS clusters",
		Explanation: `Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		Terraform:   &rules.EngineMetadata{
            GoodExamples:        terraformEncryptClusterStorageDataGoodExamples,
            BadExamples:         terraformEncryptClusterStorageDataBadExamples,
            Links:               terraformEncryptClusterStorageDataLinks,
            RemediationMarkdown: terraformEncryptClusterStorageDataRemediationMarkdown,
        },
        CloudFormation:   &rules.EngineMetadata{
            GoodExamples:        cloudFormationEncryptClusterStorageDataGoodExamples,
            BadExamples:         cloudFormationEncryptClusterStorageDataBadExamples,
            Links:               cloudFormationEncryptClusterStorageDataLinks,
            RemediationMarkdown: cloudFormationEncryptClusterStorageDataRemediationMarkdown,
        },
        Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.Encryption.EncryptStorage.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					&cluster,
					cluster.Encryption.EncryptStorage,
				)
			} else if cluster.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not specify a customer managed key for storage encryption.",
					&cluster,
					cluster.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
