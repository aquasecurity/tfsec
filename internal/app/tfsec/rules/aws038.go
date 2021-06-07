package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordExpiry            = "AWS038"
	AWSIAMPasswordExpiryDescription = "IAM Password policy should have expiry less than or equal to 90 days."
	AWSIAMPasswordExpiryImpact      = "Long life password increase the likelihood of a password eventually being compromised"
	AWSIAMPasswordExpiryResolution  = "Limit the password duration with an expiry in the policy"
	AWSIAMPasswordExpiryExplanation = `
IAM account password policies should have a maximum age specified. 

The account password policy should be set to expire passwords after 90 days or less.
`
	AWSIAMPasswordExpiryBadExample = `
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# max_password_age not set
	# ...
}
`
	AWSIAMPasswordExpiryGoodExample = `
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	max_password_age = 90
	# ...
}
`
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIAMPasswordExpiry,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIAMPasswordExpiryDescription,
			Impact:      AWSIAMPasswordExpiryImpact,
			Resolution:  AWSIAMPasswordExpiryResolution,
			Explanation: AWSIAMPasswordExpiryExplanation,
			BadExample:  AWSIAMPasswordExpiryBadExample,
			GoodExample: AWSIAMPasswordExpiryGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {
			if attr := block.GetAttribute("max_password_age"); attr == nil {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' does not have a max password age set.", block.FullName())).
						WithRange(block.Range()).
						WithSeverity(severity.Warning),
				)
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value > 90 {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("Resource '%s' has high password age.", block.FullName())).
							WithRange(attr.Range()).
							WithAttributeAnnotation(attr).
							WithSeverity(severity.Warning),
					)
				}
			}
		},
	})
}
