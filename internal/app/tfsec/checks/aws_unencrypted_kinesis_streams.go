package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSUnencryptedKinesisStream See https://github.com/tfsec/tfsec#included-checks for check info
const AWSUnencryptedKinesisStream scanner.RuleID = "AWS024"
const AWSUnencryptedKinesisStreamDescription scanner.RuleDescription = "Kinesis stream is unencrypted."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSUnencryptedKinesisStream,
		Description:    AWSUnencryptedKinesisStreamDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kinesis_stream"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			encryptionTypeAttr := block.GetAttribute("encryption_type")
			if encryptionTypeAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if encryptionTypeAttr.Type() == cty.String && encryptionTypeAttr.Value().AsString() == "" || encryptionTypeAttr.Value().AsString() == "NONE" || encryptionTypeAttr.Value().AsString() == "None" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' defines an unencrypted Kinesis Stream.", block.Name()),
						encryptionTypeAttr.Range(),
						encryptionTypeAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
