package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckBucketsHavePublicAccessBlocks = rules.RuleDef{

	Provider: provider.AWSProvider,
	Service:  "s3",
	Summary:  "S3 buckets should each define an aws_s3_bucket_public_access_block",
	Explanation: `
The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central definition for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.
`,
	Impact:     "Public access policies may be applied to sensitive data buckets",
	Resolution: "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",

	Links: []string{
		"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},

	Severity: severity.Low,
	CheckFunc: func(context *infra.Context) []*result.Result {
		var results []*result.Result
		for _, bucket := range context.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Bucket '%s' does not have a corresponding public access block.", bucket.Reference),
					Location:    bucket.Range,
				})
			}
		}
		return results
	},
}
