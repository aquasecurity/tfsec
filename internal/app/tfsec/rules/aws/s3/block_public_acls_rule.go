package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		DefSecCheck: rules.RuleDef{
			ShortCode: "FIXME",
			Provider:  provider.AWSProvider,
			Service:   "FIXME",
		},

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
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls",
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("block_public_acls") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify block_public_acls, defaults to false", resourceBlock.FullName())
				return
			}

			publicAclAttr := resourceBlock.GetAttribute("block_public_acls")
			if publicAclAttr.IsNotNil() && publicAclAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets block_public_acls explicitly to false", resourceBlock.FullName()).
					WithAttribute("")
			}
		},
	})
}
