package iam

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS042",
		Service:   "iam",
		ShortCode: "require-lowercase-in-passwords",
		Documentation: rule.RuleDocumentation{
			Summary:     "IAM Password policy should have requirement for at least one lowercase character.",
			Impact:      "Short, simple passwords are easier to compromise",
			Resolution:  "Enforce longer, more complex passwords in the policy",
			Explanation: `IAM account password policies should ensure that passwords content including at least one lowercase character.`,
			BadExample: []string{`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# require_lowercase_characters not set
	# ...
}`},
			GoodExample: []string{`
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	require_lowercase_characters = true
	# ...
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_account_password_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if attr := resourceBlock.GetAttribute("require_lowercase_characters"); attr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not require a lowercase character in the password.", resourceBlock.FullName())
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					set.AddResult().
						WithDescription("Resource '%s' explicitly specifies not requiring at least lowercase character in the password.", resourceBlock.FullName())
				}
			}
		},
	})
}
