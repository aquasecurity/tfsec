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
	AWSIAMPasswordReusePrevention            = "AWS037"
	AWSIAMPasswordReusePreventionDescription = "IAM Password policy should prevent password reuse."
	AWSIAMPasswordReusePreventionImpact      = "Password reuse increase the risk of compromised passwords being abused"
	AWSIAMPasswordReusePreventionResolution  = "Prevent password reuse in the policy"

	AWSIAMPasswordReusePreventionExplanation = `
IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.
`
	AWSIAMPasswordReusePreventionBadExample = `
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	password_reuse_prevention = 1
	# ...
}
`
	AWSIAMPasswordReusePreventionGoodExample = `
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	password_reuse_prevention = 5
	# ...
}
`
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIAMPasswordReusePrevention,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIAMPasswordReusePreventionDescription,
			Impact:      AWSIAMPasswordReusePreventionImpact,
			Resolution:  AWSIAMPasswordReusePreventionResolution,
			Explanation: AWSIAMPasswordReusePreventionExplanation,
			BadExample:  AWSIAMPasswordReusePreventionBadExample,
			GoodExample: AWSIAMPasswordReusePreventionGoodExample,
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
			if attr := resourceBlock.GetAttribute("password_reuse_prevention"); attr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have a password reuse prevention count set.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value < 5 {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has a password reuse count less than 5.", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				}
			}
		},
	})
}
