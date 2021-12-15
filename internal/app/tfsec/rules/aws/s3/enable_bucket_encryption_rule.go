package s3

import (
	"github.com/aquasecurity/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		LegacyID: "AWS017",
		BadExample: []string{`
 resource "aws_s3_bucket" "bad_example" {
   bucket = "mybucket"
 }
 `},
		GoodExample: []string{`
 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "arn"
         sse_algorithm     = "aws:kms"
       }
     }
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption",
		},
		Base: s3.CheckEncryptionIsEnabled,
	})
}
