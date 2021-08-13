package sqs

// generator-locked
import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS047",
		Service:   "sqs",
		ShortCode: "no-wildcards-in-policy-documents",
		Documentation: rule.RuleDocumentation{
			Summary:    "AWS SQS policy document has wildcard action statement.",
			Impact:     "SQS policies with wildcard actions allow more that is required",
			Resolution: "Keep policy scope to the minimum that is required to be effective",
			Explanation: `
SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.
`,
			BadExample: []string{`
resource "aws_sqs_queue_policy" "bad_example" {
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
`},
			GoodExample: []string{`
resource "aws_sqs_queue_policy" "good_example" {
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy",
				"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sqs_queue_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("policy") || !resourceBlock.GetAttribute("policy").IsString() {
				return
			}

			policyAttr := resourceBlock.GetAttribute("policy")
			rawJSON := []byte(policyAttr.Value().AsString())
			var policy struct {
				Statement []struct {
					Effect string `json:"Effect"`
					Action string `json:"Action"`
				} `json:"Statement"`
			}

			if err := json.Unmarshal(rawJSON, &policy); err == nil {
				for _, statement := range policy.Statement {
					if strings.ToLower(statement.Effect) == "allow" && (statement.Action == "*" || statement.Action == "sqs:*") {
						set.AddResult().
							WithDescription("SQS policy '%s' has a wildcard action specified.", resourceBlock.FullName()).WithAttribute(policyAttr)
					}
				}
			}

		},
	})
}
