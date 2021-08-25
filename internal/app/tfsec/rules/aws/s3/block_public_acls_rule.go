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
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 `, `
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	block_public_acls = false
 }
 `},
		GoodExample: []string{`
 resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	block_public_acls = true
 }
 `},
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Base: s3.CheckPublicACLsAreBlocked,
	})
}
