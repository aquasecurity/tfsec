package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckBucketsHavePublicAccessBlocks = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0094",
		Provider:    provider.AWSProvider,
		Service:     "s3",
		ShortCode:   "specify-public-access-block",
		Summary:     "S3 buckets should each define an aws_s3_bucket_public_access_block",
		Explanation: `The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.`,
		Impact:      "Public access policies may be applied to sensitive data buckets",
		Resolution:  "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add(
					"Bucket does not have a corresponding public access block.",
					&bucket,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
