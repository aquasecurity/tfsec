package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedSQSQueue(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	
}`,
			mustIncludeResultCode: rules.AWSUnencryptedSQSQueue,
		},
		{
			name: "check blank encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	kms_master_key_id = ""
}`,
			mustIncludeResultCode: rules.AWSUnencryptedSQSQueue,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_sqs_queue" "my-queue" {
	kms_master_key_id = "/blah"
}`,
			mustExcludeResultCode: rules.AWSUnencryptedSQSQueue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
