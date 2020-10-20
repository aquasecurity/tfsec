package checks

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSIamPolicyWildcardActions See https://github.com/tfsec/tfsec#included-checks for check info
const AWSIamPolicyWildcardActions scanner.RuleCode = "AWS046"
const AWSIamPolicyWildcardActionsDescription scanner.RuleSummary = "AWS IAM policy document has wildcard action statement."
const AWSIamPolicyWildcardActionsExplanation = `
IAM profiles should be configured with the specific, minimum set of permissions required.
`
const AWSIamPolicyWildcardActionsBadExample = `
data "aws_iam_policy_document" "my-policy" {
	statement {
		sid = "1"

        actions = [
      		"*"
    	]
	}
}
`
const AWSIamPolicyWildcardActionsGoodExample = `
data "aws_iam_policy_document" "my-policy" {
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIamPolicyWildcardActions,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIamPolicyWildcardActionsDescription,
			Explanation: AWSIamPolicyWildcardActionsExplanation,
			BadExample:  AWSIamPolicyWildcardActionsBadExample,
			GoodExample: AWSIamPolicyWildcardActionsGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"data"},
		RequiredLabels: []string{"aws_iam_policy_document"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if statementBlocks := block.GetBlocks("statement"); statementBlocks != nil {
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
								return []scanner.Result{
									check.NewResult(
										fmt.Sprintf("Resource '%s' has a wildcard action specified.", block.FullName()),
										statementBlock.Range(),
										scanner.SeverityError,
									),
								}
							}
						}
					}

				}
			}
			return nil
		},
	})
}
