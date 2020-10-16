package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedSQSQueue(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check no encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	
}`,
			mustIncludeResultCode: aws.AWSUnencryptedSQSQueue,
		},
		{
			name: "check blank encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	kms_master_key_id = ""
}`,
			mustIncludeResultCode: aws.AWSUnencryptedSQSQueue,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	kms_master_key_id = "/blah"
}`,
			mustExcludeResultCode: aws.AWSUnencryptedSQSQueue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
