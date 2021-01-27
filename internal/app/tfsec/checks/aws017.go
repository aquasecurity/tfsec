package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSUnencryptedS3Bucket scanner.RuleCode = "AWS017"
const AWSUnencryptedS3BucketDescription scanner.RuleSummary = "Unencrypted S3 bucket."
const AWSUnencryptedS3BucketExplanation = `
S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.
`
const AWSUnencryptedS3BucketBadExample = `
resource "aws_s3_bucket" "my-bucket" {
  bucket = "mybucket"
}
`
const AWSUnencryptedS3BucketGoodExample = `
resource "aws_s3_bucket" "my-bucket" {
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSUnencryptedS3Bucket,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSUnencryptedS3BucketDescription,
			Explanation: AWSUnencryptedS3BucketExplanation,
			BadExample:  AWSUnencryptedS3BucketBadExample,
			GoodExample: AWSUnencryptedS3BucketGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("server_side_encryption_configuration")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing server_side_encryption_configuration block).", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			ruleBlock := encryptionBlock.GetBlock("rule")
			if ruleBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing rule block).", block.FullName()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			applyBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
			if applyBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing apply_server_side_encryption_by_default block).", block.FullName()),
						ruleBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing sse_algorithm attribute).", block.FullName()),
						applyBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
