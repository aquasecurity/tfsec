package checks

import (
	"fmt"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSBadBucketACL See https://github.com/tfsec/tfsec#included-checks for check info
const AWSIAMPasswordReusePrevention scanner.RuleID = "AWS037"
const AWSIAMPasswordReusePreventionDescription scanner.RuleDescription = "IAM Password policy should prevent password reuse."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSIAMPasswordReusePrevention,
		Description:    AWSIAMPasswordReusePreventionDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("password_reuse_prevention"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a password reuse prevention count set.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 5 {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a password reuse count less than 5.", block.Name()),
							block.Range(),
							scanner.SeverityWarning,
						),
					}
				}
			}
			return nil
		},
	})
}
