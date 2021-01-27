package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSSqsPolicyWildcardActions(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name:                  "check with bad example",
			source:                checks.AWSSqsPolicyWildcardActionsBadExample,
			mustIncludeResultCode: checks.AWSSqsPolicyWildcardActions,
		},
		{
			name:                  "check with good example",
			source:                checks.AWSSqsPolicyWildcardActionsGoodExample,
			mustExcludeResultCode: checks.AWSSqsPolicyWildcardActions,
		},
		{
			name: "check with actions defined as an array",
			source: `
resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
    }
  ]
}
POLICY
}
`,
			mustExcludeResultCode: checks.AWSSqsPolicyWildcardActions,
		},
		{
			name: "check with prefixed wildcard action",
			source: `
resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sqs:*"
    }
  ]
}
POLICY
}
`,
			mustIncludeResultCode: checks.AWSSqsPolicyWildcardActions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
