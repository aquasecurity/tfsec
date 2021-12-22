package sqs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableQueueEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0096",
		Provider:    provider.AWSProvider,
		Service:     "sqs",
		ShortCode:   "enable-queue-encryption",
		Summary:     "Unencrypted SQS queue.",
		Impact:      "The SQS queue messages could be read if compromised",
		Resolution:  "Turn on SQS Queue encryption",
		Explanation: `Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			if queue.Encryption.KMSKeyID.IsEmpty() || queue.Encryption.KMSKeyID.EqualTo("alias/aws/sqs") {
				results.Add(
					"Queue is not encrypted with a customer managed key.",
					&queue,
					queue.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&queue)
			}
		}
		return
	},
)
