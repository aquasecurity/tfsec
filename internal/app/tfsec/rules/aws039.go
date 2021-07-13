package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordMinimumLength            = "AWS039"
	AWSIAMPasswordMinimumLengthDescription = "IAM Password policy should have minimum password length of 14 or more characters."
	AWSIAMPasswordMinimumLengthImpact      = "Short, simple passwords are easier to compromise"
	AWSIAMPasswordMinimumLengthResolution  = "Enforce longer, more complex passwords in the policy"
	AWSIAMPasswordMinimumLengthExplanation = `
IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.
`
	AWSIAMPasswordMinimumLengthBadExample = `
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# minimum_password_length not set
	# ...
}
`
	AWSIAMPasswordMinimumLengthGoodExample = `
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	minimum_password_length = 14
	# ...
}
`
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIAMPasswordMinimumLength,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIAMPasswordMinimumLengthDescription,
			Impact:      AWSIAMPasswordMinimumLengthImpact,
			Resolution:  AWSIAMPasswordMinimumLengthResolution,
			Explanation: AWSIAMPasswordMinimumLengthExplanation,
			BadExample:  AWSIAMPasswordMinimumLengthBadExample,
			GoodExample: AWSIAMPasswordMinimumLengthGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_account_password_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if attr := resourceBlock.GetAttribute("minimum_password_length"); attr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have a minimum password length set.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 14 {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has a minimum password length which is less than 14 characters.", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				}
			}
		},
	})
}
