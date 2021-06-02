package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSUnencryptedS3Bucket = "AWS017"
const AWSUnencryptedS3BucketDescription = "Unencrypted S3 bucket."
const AWSUnencryptedS3BucketImpact = "The bucket objects could be read if compromised"
const AWSUnencryptedS3BucketResolution = "Configure bucket encryption"
const AWSUnencryptedS3BucketExplanation = `
S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.
`
const AWSUnencryptedS3BucketBadExample = `
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}
`
const AWSUnencryptedS3BucketGoodExample = `
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSUnencryptedS3Bucket,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSUnencryptedS3BucketDescription,
			Impact:      AWSUnencryptedS3BucketImpact,
			Resolution:  AWSUnencryptedS3BucketResolution,
			Explanation: AWSUnencryptedS3BucketExplanation,
			BadExample:  AWSUnencryptedS3BucketBadExample,
			GoodExample: AWSUnencryptedS3BucketGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *block.Block, context *hclcontext.Context) []result.Result {

			if block.MissingChild("server_side_encryption_configuration") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing server_side_encryption_configuration block).", block.FullName()),
						).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}
			encryptionBlock := block.GetBlock("server_side_encryption_configuration")
			if encryptionBlock.MissingChild("rule") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing rule block).", block.FullName()),
						encryption).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			ruleBlock := encryptionBlock.GetBlock("rule")

			if ruleBlock.MissingChild("apply_server_side_encryption_by_default") {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing apply_server_side_encryption_by_default block).", block.FullName()),
						rule).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			applyBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr == nil {
				set.Add(
					result.New().WithDescription(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing sse_algorithm attribute).", block.FullName()),
						apply).WithRange(block.Range()).WithSeverity(
						severity.Error,
					),
				}
			}

			return nil
		},
	})
}
