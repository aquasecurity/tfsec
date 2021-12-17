package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckPublicPoliciesAreBlocked = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AWS-0087",
		Provider:   provider.AWSProvider,
		Service:    "s3",
		ShortCode:  "block-public-policy",
		Summary:    "S3 Access block should block public policy",
		Impact:     "Users could put a policy that allows public access",
		Resolution: "Prevent policies that allow public access being PUT",
		Explanation: `
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
`,

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not blocking public policies", &bucket)
			} else if bucket.PublicAccessBlock.BlockPublicPolicy.IsFalse() {
				results.Add(
					"Public access block does not block public policies",
					&bucket,
					bucket.PublicAccessBlock.BlockPublicPolicy,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
