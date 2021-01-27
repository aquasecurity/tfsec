package checks

import (
	"encoding/json"
	"fmt"
	"github.com/zclconf/go-cty/cty"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSSqsPolicyWildcardActions scanner.RuleCode = "AWS047"
const AWSSqsPolicyWildcardActionsDescription scanner.RuleSummary = "AWS SQS policy document has wildcard action statement."
const AWSSqsPolicyWildcardActionsExplanation = `
SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.
`
const AWSSqsPolicyWildcardActionsBadExample = `
resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*"
    }
  ]
}
POLICY
}
`
const AWSSqsPolicyWildcardActionsGoodExample = `
resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage"
    }
  ]
}
POLICY
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSSqsPolicyWildcardActions,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSSqsPolicyWildcardActionsDescription,
			Explanation: AWSSqsPolicyWildcardActionsExplanation,
			BadExample:  AWSSqsPolicyWildcardActionsBadExample,
			GoodExample: AWSSqsPolicyWildcardActionsGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sqs_queue_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.GetAttribute("policy").Value().Type() != cty.String {
				return nil
			}

			rawJSON := []byte(block.GetAttribute("policy").Value().AsString())
			var policy struct {
				Statement []struct {
					Effect string `json:"Effect"`
					Action string `json:"Action"`
				} `json:"Statement"`
			}

			if err := json.Unmarshal(rawJSON, &policy); err == nil {
				for _, statement := range policy.Statement {
					if strings.ToLower(statement.Effect) == "allow" && (statement.Action == "*" || statement.Action == "sqs:*") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("SQS policy '%s' has a wildcard action specified.", block.FullName()),
								block.Range(),
								scanner.SeverityError,
							),
						}
					}
				}
			}

			return nil
		},
	})
}
