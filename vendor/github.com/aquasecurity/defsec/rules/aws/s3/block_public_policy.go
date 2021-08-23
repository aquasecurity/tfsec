package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/infra"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var CheckPublicPoliciesAreBlocked = rules.RuleDef{
	Provider:  provider.AWSProvider,
	Service:   "s3",
	ShortCode: "block-public-policy",

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
	CheckFunc: func(context *infra.Context) []*result.Result {
		var results []*result.Result
		for _, block := range context.AWS.S3.PublicAccessBlocks {
			if block.BlockPublicPolicy.IsFalse() {
				results = append(results, &result.Result{
					Description: fmt.Sprintf("Public access block '%s' does not block public policies", block.Reference),
					Location:    block.BlockPublicACLs.Range,
				})
			}
		}
		return results
	},
}
