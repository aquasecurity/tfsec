package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSEfsEncryptionNotEnabled See https://github.com/liamg/tfsec#included-checks for check info
const AWSEfsEncryptionNotEnabled scanner.RuleID = "AWS030"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSEfsEncryptionNotEnabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_efs_file_system"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {


			efsEnabledAttr := block.GetAttribute("encrypted")
			efsEncryptionStatusAttr := block.GetAttribute("kms_key_id")


			if efsEncryptionStatusAttr == nil || efsEnabledAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled EFS Encryption.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if efsEncryptionStatusAttr.Type() == cty.Bool && efsEncryptionStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled EFS Encryption.", block.Name()),
						efsEncryptionStatusAttr.Range(),
						efsEncryptionStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}