package s3

import (
	"github.com/aquasecurity/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS075",
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
		},
		Base: s3.CheckPublicBucketsAreRestricted,
	})
}
