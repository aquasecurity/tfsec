package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSNoKMSAutoRotate See https://github.com/tfsec/tfsec#included-checks for check info
const AWSNoKMSAutoRotate scanner.RuleCode = "AWS019"
const AWSNoKMSAutoRotateDescription scanner.RuleSummary = "A KMS key is not configured to auto-rotate."
const AWSNoKMSAutoRotateImpact = "Long life KMS keys increase the attack surface when compromised"
const AWSNoKMSAutoRotateResolution = "Configure KMS key to auto rotate"
const AWSNoKMSAutoRotateExplanation = `
You should configure your KMS keys to auto rotate to maintain security and defend against compromise.
`
const AWSNoKMSAutoRotateBadExample = `
resource "aws_kms_key" "bad_example" {
	enable_key_rotation = false
}
`
const AWSNoKMSAutoRotateGoodExample = `
resource "aws_kms_key" "good_example" {
	enable_key_rotation = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSNoKMSAutoRotate,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSNoKMSAutoRotateDescription,
			Impact:      AWSNoKMSAutoRotateImpact,
			Resolution:  AWSNoKMSAutoRotateResolution,
			Explanation: AWSNoKMSAutoRotateExplanation,
			BadExample:  AWSNoKMSAutoRotateBadExample,
			GoodExample: AWSNoKMSAutoRotateGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kms_key"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			keyUsageAttr := block.GetAttribute("key_usage")

			if keyUsageAttr != nil && keyUsageAttr.Equals("SIGN_VERIFY") {
				return nil
			}

			keyRotationAttr := block.GetAttribute("enable_key_rotation")

			if keyRotationAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			if keyRotationAttr.Type() == cty.Bool && keyRotationAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' does not have KMS Key auto-rotation enabled.", block.FullName()),
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
