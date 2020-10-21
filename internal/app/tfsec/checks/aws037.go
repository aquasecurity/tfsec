package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const (
	AWSIAMPasswordReusePrevention            scanner.RuleCode    = "AWS037"
	AWSIAMPasswordReusePreventionDescription scanner.RuleSummary = "IAM Password policy should prevent password reuse."

	AWSIAMPasswordReusePreventionExplanation = `
IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.
`
	AWSIAMPasswordReusePreventionBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	password_reuse_prevention = 1
	# ...
}
`
	AWSIAMPasswordReusePreventionGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	password_reuse_prevention = 5
	# ...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordReusePrevention,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordReusePreventionDescription,
			Explanation: AWSIAMPasswordReusePreventionExplanation,
			BadExample:  AWSIAMPasswordReusePreventionBadExample,
			GoodExample: AWSIAMPasswordReusePreventionGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("password_reuse_prevention"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a password reuse prevention count set.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 5 {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a password reuse count less than 5.", block.FullName()),
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
