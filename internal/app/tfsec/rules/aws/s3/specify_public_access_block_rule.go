package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS098",
		Service:   "s3",
		ShortCode: "specify-public-access-block",
		Documentation: rule.RuleDocumentation{
			Summary: "S3 buckets should each define an aws_s3_bucket_public_access_block",
			Explanation: `
The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central definition for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.
`,
			Impact:     "Public access policies may be applied to sensitive data buckets",
			Resolution: "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
			BadExample: []string{`
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
  
resource "aws_s3_bucket_public_access_block" "example" {
	bucket = aws_s3_bucket.example.id
	block_public_acls   = true
	block_public_policy = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			blocks, err := module.GetReferencingResources(resourceBlock, "aws_s3_bucket_public_access_block", "bucket")
			if err != nil || len(blocks) == 0 {
				set.AddResult().
					WithDescription("Resource %s has no associated aws_s3_bucket_public_access_block.", resourceBlock.FullName())
			}
		},
	})
}
