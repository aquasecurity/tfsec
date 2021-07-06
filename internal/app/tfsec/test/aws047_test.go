package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSSqsPolicyWildcardActions(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check with bad example",
			source:                rules.AWSSqsPolicyWildcardActionsBadExample,
			mustIncludeResultCode: rules.AWSSqsPolicyWildcardActions,
		},
		{
			name:                  "check with good example",
			source:                rules.AWSSqsPolicyWildcardActionsGoodExample,
			mustExcludeResultCode: rules.AWSSqsPolicyWildcardActions,
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
			mustExcludeResultCode: rules.AWSSqsPolicyWildcardActions,
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
			mustIncludeResultCode: rules.AWSSqsPolicyWildcardActions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
