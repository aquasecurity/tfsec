package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckEncryptionIsEnabled = rules.RuleDef{

	Provider:   provider.AWSProvider,
	Service:    "s3",
	Summary:    "Unencrypted S3 bucket.",
	Impact:     "The bucket objects could be read if compromised",
	Resolution: "Configure bucket encryption",
	Explanation: `
S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.
`,

	Links: []string{
		"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
	},

	Severity: severity.High,
	CheckFunc: func(context *infra.Context) []*result.Result {

		var results []*result.Result
		for _, bucket := range context.AWS.S3.Buckets {
			if bucket.Encryption.Enabled.IsFalse() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Resource '%s' does not have encryption enabled", bucket.Reference),
					Location:    bucket.Encryption.Enabled.Range,
				})
			}
		}
		return results
	},
}
