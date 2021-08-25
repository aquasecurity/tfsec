package s3

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS098",
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
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Base: s3.CheckBucketsHavePublicAccessBlocks,
	})
}
