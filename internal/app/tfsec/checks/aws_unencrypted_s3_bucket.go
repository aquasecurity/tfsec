package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedS3Bucket See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedS3Bucket scanner.RuleID = "AWS017"
const AWSUnencryptedS3BucketDescription scanner.RuleDescription = "Unencrypted S3 bucket."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedS3Bucket,
		Description:    AWSUnencryptedS3BucketDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("server_side_encryption_configuration")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing server_side_encryption_configuration block).", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			ruleBlock := encryptionBlock.GetBlock("rule")
			if ruleBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing rule block).", block.Name()),
						encryptionBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			applyBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
			if applyBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing apply_server_side_encryption_by_default block).", block.Name()),
						ruleBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing sse_algorithm attribute).", block.Name()),
						applyBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
