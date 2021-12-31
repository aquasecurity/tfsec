package s3

import (
	"github.com/aquasecurity/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS074",
		BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.bad_example.id
}
 `, `
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.bad_example.id
  block_public_acls = false
}
 `},
		GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.good_example.id
  block_public_acls = true
}
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls",
		},
		Base: s3.CheckPublicACLsAreBlocked,
	})
}
