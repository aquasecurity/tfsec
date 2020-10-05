package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSNoKMSAutoRotate See https://github.com/tfsec/tfsec#included-checks for check info
const AWSNoKMSAutoRotate scanner.RuleID = "AWS019"
const AWSNoKMSAutoRotateDescription scanner.RuleDescription = "A KMS key is not configured to auto-rotate."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSNoKMSAutoRotate,
		Description:    AWSNoKMSAutoRotateDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kms_key"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			keyRotationAttr := block.GetAttribute("enable_key_rotation")

			if keyRotationAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			if keyRotationAttr.Type() == cty.Bool && keyRotationAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", block.Name()),
						keyRotationAttr.Range(),
						keyRotationAttr,
						scanner.SeverityWarning,
					),
				}
			}

			return nil
		},
	})
}
