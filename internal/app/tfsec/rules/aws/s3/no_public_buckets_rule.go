package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS075",
		Service:   "s3",
		ShortCode: "no-public-buckets",
		Documentation: rule.RuleDocumentation{
			Summary:    "S3 Access block should restrict public bucket to limit access",
			Impact:     "Public buckets can be accessed by anyone",
			Resolution: "Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)",
			Explanation: `
S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.
`,
			BadExample: []string{`
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = false
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡",
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("restrict_public_buckets") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify restrict_public_buckets, defaults to false", resourceBlock.FullName())
				return
			}

			restrictPublicAttr := resourceBlock.GetAttribute("restrict_public_buckets")
			if restrictPublicAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets restrict_public_buckets explicitly to false", resourceBlock.FullName()).
					WithAttribute(restrictPublicAttr)
			}
		},
	})
}
