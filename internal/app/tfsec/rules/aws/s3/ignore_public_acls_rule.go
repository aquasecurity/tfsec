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
		LegacyID:  "AWS073",
		Service:   "s3",
		ShortCode: "ignore-public-acls",
		Documentation: rule.RuleDocumentation{
			Summary:    "S3 Access Block should Ignore Public Acl",
			Impact:     "PUT calls with public ACLs specified can make objects public",
			Resolution: "Enable ignoring the application of public ACLs in PUT calls",
			Explanation: `
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
`,
			BadExample: []string{`
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = false
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	ignore_public_acls = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("ignore_public_acls") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify ignore_public_acls, defaults to false", resourceBlock.FullName())
				return
			}

			ignorePublicAclsAttr := resourceBlock.GetAttribute("ignore_public_acls")
			if ignorePublicAclsAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets ignore_public_acls explicitly to false", resourceBlock.FullName()).
					WithAttribute(ignorePublicAclsAttr)
			}
		},
	})
}
