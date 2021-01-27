package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordMinimumLength            scanner.RuleCode    = "AWS039"
	AWSIAMPasswordMinimumLengthDescription scanner.RuleSummary = "IAM Password policy should have minimum password length of 14 or more characters."

	AWSIAMPasswordMinimumLengthExplanation = `
IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.
`
	AWSIAMPasswordMinimumLengthBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	# minimum_password_length not set
	# ...
}
`
	AWSIAMPasswordMinimumLengthGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	# ...
	minimum_password_length = 14
	# ...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordMinimumLength,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordMinimumLengthDescription,
			Explanation: AWSIAMPasswordMinimumLengthExplanation,
			BadExample:  AWSIAMPasswordMinimumLengthBadExample,
			GoodExample: AWSIAMPasswordMinimumLengthGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("minimum_password_length"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a minimum password length set.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 14 {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a minimum password length which is less than 14 characters.", block.FullName()),
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
