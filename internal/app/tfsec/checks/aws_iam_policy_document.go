package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSIamPolicyWildcardActions See https://github.com/tfsec/tfsec#included-checks for check info
const AWSIamPolicyWildcardActions scanner.RuleID = "AWS046"
const AWSIamPolicyWildcardActionsDescription scanner.RuleSummary = "AWS IAM policy document has wildcard action statement."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIamPolicyWildcardActions,
		Documentation: scanner.CheckDocumentation{
			Summary: AWSIamPolicyWildcardActionsDescription,
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"data"},
		RequiredLabels: []string{"aws_iam_policy_document"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if statementBlocks := block.GetBlocks("statement"); statementBlocks != nil {
				for _, statementBlock := range statementBlocks {
					if actions := statementBlock.GetAttribute("actions"); actions != nil {
						actionValues := actions.Value().AsValueSlice()
						for _, actionValue := range actionValues {
							if actionValue.AsString() == "*" {
								return []scanner.Result{
									check.NewResult(
										fmt.Sprintf("Resource '%s' has a wildcard action specified.", block.Name()),
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
