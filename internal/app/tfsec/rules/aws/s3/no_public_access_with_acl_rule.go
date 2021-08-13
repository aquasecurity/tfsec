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
		LegacyID:  "AWS001",
		Service:   "s3",
		ShortCode: "no-public-access-with-acl",
		Documentation: rule.RuleDocumentation{
			Summary: "S3 Bucket has an ACL defined which allows public access.",
			Explanation: `
S3 bucket permissions should be set to deny public access unless explicitly required.

Granting write access publicly with <code>public-read-write</code> is especially dangerous as you will be billed for any uploaded files.

Additionally, you should not use the <code>authenticated-read</code> canned ACL, as this provides read access to any authenticated AWS user, not just AWS users within your organisation.
`,
			Impact:     "The contents of the bucket can be accessed publicly",
			Resolution: "Apply a more restrictive bucket ACL",
			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
				"https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("acl") {
				return
			}

			aclAttr := resourceBlock.GetAttribute("acl")
			if aclAttr.IsAny("public-read", "public-read-write", "website") {
				set.AddResult().
					WithDescription("Resource '%s' has an ACL which allows public access.", resourceBlock.FullName()).
					WithAttribute(aclAttr)
			} else if aclAttr.Equals("authenticated-read") {
				set.AddResult().
					WithDescription("Resource '%s' has an ACL which allows access to any authenticated AWS user, not just users within the target account.", resourceBlock.FullName())
			}
		},
	})
}
