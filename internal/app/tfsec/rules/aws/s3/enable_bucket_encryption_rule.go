package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS017",
		Service:   "s3",
		ShortCode: "enable-bucket-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted S3 bucket.",
			Impact:     "The bucket objects could be read if compromised",
			Resolution: "Configure bucket encryption",
			Explanation: `
S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.
`,
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
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			if resourceBlock.MissingChild("server_side_encryption_configuration") {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted S3 bucket (missing server_side_encryption_configuration block).", resourceBlock.FullName())
				return
			}
			encryptionBlock := resourceBlock.GetBlock("server_side_encryption_configuration")
			if encryptionBlock.MissingChild("rule") {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted S3 bucket (missing rule block).", resourceBlock.FullName())
				return
			}

			ruleBlock := encryptionBlock.GetBlock("rule")
			if ruleBlock.MissingChild("apply_server_side_encryption_by_default") {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted S3 bucket (missing apply_server_side_encryption_by_default block).", resourceBlock.FullName()).WithBlock(ruleBlock)
				return
			}

			applyBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines an unencrypted S3 bucket (missing sse_algorithm attribute).", resourceBlock.FullName()).WithBlock(applyBlock)
			}

		},
	})
}
