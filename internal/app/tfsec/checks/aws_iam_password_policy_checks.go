package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const (
	AWSIAMPasswordReusePrevention            scanner.RuleID      = "AWS037"
	AWSIAMPasswordReusePreventionDescription scanner.RuleSummary = "IAM Password policy should prevent password reuse."

	AWSIAMPasswordReusePreventionExplanation = `
IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.
`
	AWSIAMPasswordReusePreventionBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	password_reuse_prevention = 1
	...
}
`
	AWSIAMPasswordReusePreventionGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	password_reuse_prevention = 5
	...
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

const (
	AWSIAMPasswordExpiry            scanner.RuleID      = "AWS038"
	AWSIAMPasswordExpiryDescription scanner.RuleSummary = "IAM Password policy should have expiry less than or equal to 90 days."

	AWSIAMPasswordExpiryExplanation = `
IAM account password policies should have a maximum age specified. 

The account password policy should be set to expire passwords after 90 days or less.
`
	AWSIAMPasswordExpiryBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// max_password_age not set
	...
}
`
	AWSIAMPasswordExpiryGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	max_password_age = 90
	...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordExpiry,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordExpiryDescription,
			Explanation: AWSIAMPasswordExpiryExplanation,
			BadExample:  AWSIAMPasswordExpiryBadExample,
			GoodExample: AWSIAMPasswordExpiryGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("max_password_age"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a max password age set.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value > 90 {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a max age set which is greated than 90 days.", block.Name()),
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

const (
	AWSIAMPasswordMinimumLength            scanner.RuleID      = "AWS039"
	AWSIAMPasswordMinimumLengthDescription scanner.RuleSummary = "IAM Password policy should have minimum password length of 14 or more characters."

	AWSIAMPasswordMinimumLengthExplanation = `
IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.
`
	AWSIAMPasswordMinimumLengthBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// minimum_password_length not set
	...
}
`
	AWSIAMPasswordMinimumLengthGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	minimum_password_length = 14
	...
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
						fmt.Sprintf("Resource '%s' does not have a minimum password length set.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 14 {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has a minimum password length which is less than 14 characters.", block.Name()),
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

const (
	AWSIAMPasswordRequiresSymbol            scanner.RuleID      = "AWS040"
	AWSIAMPasswordRequiresSymbolDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one symbol in the password."

	AWSIAMPasswordRequiresSymbolExplanation = `
IAM account password policies should ensure that passwords content including a symbol.
`
	AWSIAMPasswordRequiresSymbolBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// require_symbols not set
	...
}
`
	AWSIAMPasswordRequiresSymbolGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	require_symbols = true
	...
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
						fmt.Sprintf("Resource '%s' does not require a symbol in the password.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least one symbol in the password.", block.Name()),
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

const (
	AWSIAMPasswordRequiresNumber            scanner.RuleID      = "AWS041"
	AWSIAMPasswordRequiresNumberDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one number in the password."

	AWSIAMPasswordRequiresNumberExplanation = `
IAM account password policies should ensure that passwords content including at least one number.
`
	AWSIAMPasswordRequiresNumberBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// require_numbers not set
	...
}
`
	AWSIAMPasswordRequiresNumberGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	require_numbers = true
	...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordRequiresNumber,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordRequiresNumberDescription,
			Explanation: AWSIAMPasswordRequiresNumberExplanation,
			BadExample:  AWSIAMPasswordRequiresNumberBadExample,
			GoodExample: AWSIAMPasswordRequiresNumberGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("require_numbers"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not require a number in the password.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least one number in the password.", block.Name()),
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

const (
	AWSIAMPasswordRequiresLowercaseCharacter            scanner.RuleID      = "AWS042"
	AWSIAMPasswordRequiresLowercaseCharacterDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one lowercase character."

	AWSIAMPasswordRequiresLowercaseCharacterExplanation = `
IAM account password policies should ensure that passwords content including at least one lowercase character.
`
	AWSIAMPasswordRequiresLowercaseCharacterBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// require_lowercase_characters not set
	...
}
`
	AWSIAMPasswordRequiresLowercaseCharacterGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	require_lowercase_characters = true
	...
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
						fmt.Sprintf("Resource '%s' does not require a lowercase character in the password.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least lowercase character in the password.", block.Name()),
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

// AWSIAMPasswordRequiresUppercaseCharacter See https://github.com/tfsec/tfsec#included-checks for check info
const (
	AWSIAMPasswordRequiresUppercaseCharacter            scanner.RuleID      = "AWS043"
	AWSIAMPasswordRequiresUppercaseCharacterDescription scanner.RuleSummary = "IAM Password policy should have requirement for at least one uppercase character."

	AWSIAMPasswordRequiresUppercaseCharacterExplanation = `
IAM account password policies should ensure that passwords content including at least one uppercase character.
`
	AWSIAMPasswordRequiresUppercaseCharacterBadExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	// require_uppercase_characters not set
	...
}
`
	AWSIAMPasswordRequiresUppercaseCharacterGoodExample = `
resource "aws_iam_account_password_policy" "strict" {
	...
	require_uppercase_characters = true
	...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordRequiresUppercaseCharacter,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordRequiresUppercaseCharacterDescription,
			Explanation: AWSIAMPasswordRequiresUppercaseCharacterExplanation,
			BadExample:  AWSIAMPasswordRequiresUppercaseCharacterBadExample,
			GoodExample: AWSIAMPasswordRequiresUppercaseCharacterGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("require_uppercase_characters"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not require an uppercase character in the password.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least one uppercase character in the password.", block.Name()),
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
