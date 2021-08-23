package s3

// generator-locked
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
			ShortCode: "abnksdjf",
			Service:   "s3",
			Provider:  provider.AWSProvider,
		},

		LegacyID: "AWS073",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket_public_access_block"},
		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("ignore_public_acls") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify ignore_public_acls, defaults to false", resourceBlock.FullName())
				return
			}

			ignorePublicAclsAttr := resourceBlock.GetAttribute("ignore_public_acls")
			if ignorePublicAclsAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets ignore_public_acls explicitly to false", resourceBlock.FullName()).
					WithAttribute("")
			}
		},
	})
}
