package sqs

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSSqsPolicyWildcardActions(t *testing.T) {
	expectedCode := "aws-sqs-no-wildcards-in-policy-documents"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
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
			mustExcludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
