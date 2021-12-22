package s3

import (
	"github.com/aquasecurity/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
		},
		Base: s3.CheckForPublicACL,
	})
}
