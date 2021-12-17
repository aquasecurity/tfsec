package rds

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptInstanceStorageData = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0080",
		Provider:   provider.AWSProvider,
		Service:    "rds",
		ShortCode:  "encrypt-instance-storage-data",
		Summary:    "RDS encryption has not been enabled at a DB Instance level.",
		Impact:     "Data can be read from RDS instances if compromised",
		Resolution: "Enable encryption for RDS instances",
		Explanation: `Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, instance := range s.AWS.RDS.Instances {
			if !instance.ReplicationSourceARN.IsEmpty() {
				continue
			}
			if instance.Encryption.EncryptStorage.IsFalse() {
				results.Add(
					"Instance does not have storage encryption enabled.",
					&instance,
					instance.Encryption.EncryptStorage,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
