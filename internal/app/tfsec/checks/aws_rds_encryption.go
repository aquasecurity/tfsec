package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSRdsEncryptionNotEnabled See https://github.com/liamg/tfsec#included-checks for check info
const AWSRdsEncryptionNotEnabled scanner.RuleID = "AWS027"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSRdsEncryptionNotEnabled,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			rdsEncryptionStatusAttr := block.GetAttribute("kms_key_id")

			if rdsEncryptionStatusAttr == nil  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Encryption.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if rdsEncryptionStatusAttr.Type() == cty.Bool && rdsEncryptionStatusAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines a disabled RDS Instance Encryption.", block.Name()),
						rdsEncryptionStatusAttr.Range(),
						rdsEncryptionStatusAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}