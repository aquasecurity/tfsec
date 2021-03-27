package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRestrictPublicBucketS3 scanner.RuleCode = "AWS075"
const AWSRestrictPublicBucketS3Description scanner.RuleSummary = "S3 Access block should restrict public bucket to limit access"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRestrictPublicBucketS3,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRestrictPublicBucketS3Description,
			Explanation: AWSRestrictPublicBucketS3Explanation,
			BadExample:  AWSRestrictPublicBucketS3BadExample,
			GoodExample: AWSRestrictPublicBucketS3GoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket_public_access_block"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("restrict_public_buckets") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not specify restrict_public_buckets, defaults to false", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			attr := block.GetAttribute("restrict_public_buckets")
			if attr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' sets restrict_public_buckets explicitly to false", block.FullName()),
						attr.Range(),
						attr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
