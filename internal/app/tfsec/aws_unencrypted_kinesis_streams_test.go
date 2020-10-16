package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedKinesisStream(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check no encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	
}`,
			mustIncludeResultCode: aws.AWSUnencryptedKinesisStream,
		},
		{
			name: "check blank encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "NONE"
}`,
			mustIncludeResultCode: aws.AWSUnencryptedKinesisStream,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
}`,
			mustExcludeResultCode: aws.AWSUnencryptedKinesisStream,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
