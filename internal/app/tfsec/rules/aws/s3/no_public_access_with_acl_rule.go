package s3

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules/aws/s3"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS001",
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
		DefSecCheck: s3.CheckForPublicACL,
	})
}
