package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSRestrictPublicBucketS3 = "AWS075"
const AWSRestrictPublicBucketS3Description = "S3 Access block should restrict public bucket to limit access"
const AWSRestrictPublicBucketS3Impact = "Public buckets can be accessed by anyone"
const AWSRestrictPublicBucketS3Resolution = "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)"
const AWSRestrictPublicBucketS3Explanation = `
S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.
`
const AWSRestrictPublicBucketS3BadExample = `
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = false
}
`
const AWSRestrictPublicBucketS3GoodExample = `
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRestrictPublicBucketS3,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSRestrictPublicBucketS3Description,
			Impact:      AWSRestrictPublicBucketS3Impact,
			Resolution:  AWSRestrictPublicBucketS3Resolution,
			Explanation: AWSRestrictPublicBucketS3Explanation,
			BadExample:  AWSRestrictPublicBucketS3BadExample,
			GoodExample: AWSRestrictPublicBucketS3GoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("restrict_public_buckets") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not specify restrict_public_buckets, defaults to false", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			attr := resourceBlock.GetAttribute("restrict_public_buckets")
			if attr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' sets restrict_public_buckets explicitly to false", resourceBlock.FullName())).
						WithRange(attr.Range()).
						WithAttributeAnnotation(attr),
				)
			}
		},
	})
}
