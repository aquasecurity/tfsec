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
		LegacyID:  "AWS076",
		Service:   "s3",
		ShortCode: "block-public-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "S3 Access block should block public policy",
			Impact:     "Users could put a policy that allows public access",
			Resolution: "Prevent policies that allow public access being PUT",
			Explanation: `
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
`,
			BadExample: []string{`
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_policy = false
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	block_public_policy = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy",
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("block_public_policy") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify block_public_policy, defaults to false", resourceBlock.FullName())
				return
			}

			attr := resourceBlock.GetAttribute("block_public_policy")
			if attr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets block_public_policy explicitly to false", resourceBlock.FullName()).
					WithAttribute(attr)
			}
		},
	})
}
