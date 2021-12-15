package ecr

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRepositoryCustomerKey = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0033",
		Provider:    provider.AWSProvider,
		Service:     "ecr",
		ShortCode:   "repository-customer-key",
		Summary:     "ECR Repository should use customer managed keys to allow more control",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Use customer managed keys",
		Explanation: `Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.Encryption.Type.NotEqualTo(ecr.EncryptionTypeKMS) {
				results.Add(
					"Repository is not encrypted using KMS.",
					&repo,
					repo.Encryption.Type,
				)
			} else if repo.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Repository encryption does not use a customer managed KMS key.",
					&repo,
					repo.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)
