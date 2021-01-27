package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordRequiresSymbol            scanner.RuleCode    = "AWS040"
	AWSIAMPasswordRequiresSymbolDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one symbol in the password."

	AWSIAMPasswordRequiresSymbolExplanation = `
IAM account password policies should ensure that passwords content including a symbol.
`
	AWSIAMPasswordRequiresSymbolBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	# require_symbols not set
	# ...
}
`
	AWSIAMPasswordRequiresSymbolGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	require_symbols = true
	# ...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordRequiresSymbol,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordRequiresSymbolDescription,
			Explanation: AWSIAMPasswordRequiresSymbolExplanation,
			BadExample:  AWSIAMPasswordRequiresSymbolBadExample,
			GoodExample: AWSIAMPasswordRequiresSymbolGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("require_symbols"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not require a symbol in the password.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least one symbol in the password.", block.FullName()),
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
