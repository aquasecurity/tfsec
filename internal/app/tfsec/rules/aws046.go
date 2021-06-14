package rules

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

// AWSIamPolicyWildcardActions See https://github.com/tfsec/tfsec#included-checks for check info
const AWSIamPolicyWildcardActions = "AWS046"
const AWSIamPolicyWildcardActionsDescription = "AWS IAM policy document has wildcard action statement."
const AWSIamPolicyWildcardActionsImpact = "IAM policies with wildcard actions allow more that is required"
const AWSIamPolicyWildcardActionsResolution = "Keep policy scope to the minimum that is required to be effective"
const AWSIamPolicyWildcardActionsExplanation = `
IAM profiles should be configured with the specific, minimum set of permissions required.
`
const AWSIamPolicyWildcardActionsBadExample = `
data "aws_iam_policy_document" "bad_example" {
	statement {
		sid = "1"

        actions = [
      		"*"
    	]
	}
}
`
const AWSIamPolicyWildcardActionsGoodExample = `
data "aws_iam_policy_document" "good_example" {
	statement {
		sid = "1"

        actions = [
      		"s3:ListAllMyBuckets",
      		"ec2:DescribeInstances"
    	]
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSIamPolicyWildcardActions,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSIamPolicyWildcardActionsDescription,
			Impact:      AWSIamPolicyWildcardActionsImpact,
			Resolution:  AWSIamPolicyWildcardActionsResolution,
			Explanation: AWSIamPolicyWildcardActionsExplanation,
			BadExample:  AWSIamPolicyWildcardActionsBadExample,
			GoodExample: AWSIamPolicyWildcardActionsGoodExample,
			Links:       []string{},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"data"},
		RequiredLabels: []string{"aws_iam_policy_document"},
		CheckFunc: func(set result.Set, resourceBlock *block.Block, _ *hclcontext.Context) {

			if statementBlocks := resourceBlock.GetBlocks("statement"); statementBlocks != nil {
				for _, statementBlock := range statementBlocks {
					if effect := statementBlock.GetAttribute("effect"); effect != nil {
						if effect.Type() == cty.String && strings.ToLower(effect.Value().AsString()) == "deny" {
							continue
						}
					}
					if actions := statementBlock.GetAttribute("actions"); actions != nil {
						actionValues := actions.Value().AsValueSlice()
						for _, actionValue := range actionValues {
							if actionValue.AsString() == "*" {
								set.Add(
									result.New(resourceBlock).
										WithDescription(fmt.Sprintf("Resource '%s' has a wildcard action specified.", resourceBlock.FullName())).
										WithRange(statementBlock.Range()).
										WithSeverity(severity.Error),
								)
							}
						}
					}

				}
			}
		},
	})
}
