package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

const AWSS3BucketShouldHavePublicAccessBlock = "AWS098"
const AWSS3BucketShouldHavePublicAccessBlockDescription = "S3 buckets should each define an aws_s3_bucket_public_access_block"
const AWSS3BucketShouldHavePublicAccessBlockImpact = "Public access policies may be applied to sensitive data buckets"
const AWSS3BucketShouldHavePublicAccessBlockResolution = "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies"
const AWSS3BucketShouldHavePublicAccessBlockExplanation = `
The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central definition for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.
`
const AWSS3BucketShouldHavePublicAccessBlockBadExample = `
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
`
const AWSS3BucketShouldHavePublicAccessBlockGoodExample = `
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
  
resource "aws_s3_bucket_public_access_block" "example" {
	bucket = aws_s3_bucket.example.id
	block_public_acls   = true
	block_public_policy = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSS3BucketShouldHavePublicAccessBlock,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSS3BucketShouldHavePublicAccessBlockDescription,
			Explanation: AWSS3BucketShouldHavePublicAccessBlockExplanation,
			Impact:      AWSS3BucketShouldHavePublicAccessBlockImpact,
			Resolution:  AWSS3BucketShouldHavePublicAccessBlockResolution,
			BadExample:  AWSS3BucketShouldHavePublicAccessBlockBadExample,
			GoodExample: AWSS3BucketShouldHavePublicAccessBlockGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {
			blocks, err := ctx.GetReferencingResources(resourceBlock, "aws_s3_bucket_public_access_block", "bucket")
			if err != nil || len(blocks) == 0 {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource %s has no associated aws_s3_bucket_public_access_block.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			}
		},
	})
}
