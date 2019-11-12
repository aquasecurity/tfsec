package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedS3Bucket See https://github.com/liamg/tfsec#included-checks for check info
const AWSUnencryptedS3Bucket scanner.CheckCode = "AWS017"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedS3Bucket,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionBlock := block.GetBlock("server_side_encryption_configuration")
			if encryptionBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing server_side_encryption_configuration block).", block.Name()),
						block.Range(),
					),
				}
			}

			ruleBlock := encryptionBlock.GetBlock("rule")
			if ruleBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing rule block).", block.Name()),
						encryptionBlock.Range(),
					),
				}
			}

			applyBlock := ruleBlock.GetBlock("apply_server_side_encryption_by_default")
			if applyBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing apply_server_side_encryption_by_default block).", block.Name()),
						ruleBlock.Range(),
					),
				}
			}

			if sseAttr := applyBlock.GetAttribute("sse_algorithm"); sseAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted S3 bucket (missing sse_algorithm attribute).", block.Name()),
						applyBlock.Range(),
					),
				}
			}

			return nil
		},
	})
}
