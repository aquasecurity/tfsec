package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedSQSQueue See https://github.com/liamg/tfsec#included-checks for check info
const AWSUnencryptedSNSTopic scanner.CheckCode = "AWS016"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedSNSTopic,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			kmsKeyIDAttr := block.GetAttribute("kms_master_key_id")
			if kmsKeyIDAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.Name()),
						block.Range(),
					),
				}
			} else if kmsKeyIDAttr.Type() != cty.String || kmsKeyIDAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted SNS topic.", block.Name()),
						kmsKeyIDAttr.Range(),
						kmsKeyIDAttr,
					),
				}
			}

			return nil
		},
	})
}
