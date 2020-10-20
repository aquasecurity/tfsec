package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordRequiresLowercaseCharacter            scanner.RuleCode    = "AWS042"
	AWSIAMPasswordRequiresLowercaseCharacterDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one lowercase character."

	AWSIAMPasswordRequiresLowercaseCharacterExplanation = `
IAM account password policies should ensure that passwords content including at least one lowercase character.
`
	AWSIAMPasswordRequiresLowercaseCharacterBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	# require_lowercase_characters not set
	# ...
}
`
	AWSIAMPasswordRequiresLowercaseCharacterGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	require_lowercase_characters = true
	# ...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordRequiresLowercaseCharacter,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordRequiresLowercaseCharacterDescription,
			Explanation: AWSIAMPasswordRequiresLowercaseCharacterExplanation,
			BadExample:  AWSIAMPasswordRequiresLowercaseCharacterBadExample,
			GoodExample: AWSIAMPasswordRequiresLowercaseCharacterGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("require_lowercase_characters"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not require a lowercase character in the password.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least lowercase character in the password.", block.FullName()),
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
