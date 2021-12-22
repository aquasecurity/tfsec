package ebs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0027",
		Provider:    provider.AWSProvider,
		Service:     "ebs",
		ShortCode:   "encryption-customer-key",
		Summary:     "EBS volume encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, volume := range s.AWS.EBS.Volumes {
			if !volume.IsManaged() {
				continue
			}
			if volume.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"EBS volume does not use a customer-managed KMS key.",
					volume.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)
