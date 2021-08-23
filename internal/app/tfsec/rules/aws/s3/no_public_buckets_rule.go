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
			ShortCode: "blah blah",
			Service:   "s3",
			Provider:  provider.AWSProvider,
		},

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
			"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
		},
		CheckTerraform: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("restrict_public_buckets") {
				set.AddResult().
					WithDescription("Resource '%s' does not specify restrict_public_buckets, defaults to false", resourceBlock.FullName())
				return
			}

			restrictPublicAttr := resourceBlock.GetAttribute("restrict_public_buckets")
			if restrictPublicAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' sets restrict_public_buckets explicitly to false", resourceBlock.FullName()).
					WithAttribute("")
			}
		},
	})
}
