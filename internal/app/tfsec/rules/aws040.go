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
	AWSIAMPasswordRequiresSymbol            = "AWS040"
	AWSIAMPasswordRequiresSymbolDescription = "IAM Password policy should have requirement for at least one symbol in the password."
	AWSIAMPasswordRequiresSymbolImpact      = "Short, simple passwords are easier to compromise"
	AWSIAMPasswordRequiresSymbolResolution  = "Enforce longer, more complex passwords in the policy"
	AWSIAMPasswordRequiresSymbolExplanation = `
IAM account password policies should ensure that passwords content including a symbol.
`
	AWSIAMPasswordRequiresSymbolBadExample = `
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# require_symbols not set
	# ...
}
`
	AWSIAMPasswordRequiresSymbolGoodExample = `
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	require_symbols = true
	# ...
}
`
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIAMPasswordRequiresSymbol,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIAMPasswordRequiresSymbolDescription,
			Impact:      AWSIAMPasswordRequiresSymbolImpact,
			Resolution:  AWSIAMPasswordRequiresSymbolResolution,
			Explanation: AWSIAMPasswordRequiresSymbolExplanation,
			BadExample:  AWSIAMPasswordRequiresSymbolBadExample,
			GoodExample: AWSIAMPasswordRequiresSymbolGoodExample,
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
			if attr := resourceBlock.GetAttribute("require_symbols"); attr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not require a symbol in the password.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if attr.Value().Type() == cty.Bool {
				if attr.Value().False() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' explicitly specifies not requiring at least one symbol in the password.", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				}
			}
		},
	})
}
