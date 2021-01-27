package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedKinesisStream(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check no encryption specified for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	
}`,
			mustIncludeResultCode: checks.AWSUnencryptedKinesisStream,
		},
		{
			name: "check encryption disabled for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "NONE"
}`,
			mustIncludeResultCode: checks.AWSUnencryptedKinesisStream,
		},
		{
			name: "check no encryption key id specified for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
}`,
			mustIncludeResultCode: checks.AWSUnencryptedKinesisStream,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
	kms_key_id = "my/key"
}`,
			mustExcludeResultCode: checks.AWSUnencryptedKinesisStream,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
