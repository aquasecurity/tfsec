package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedKinesisStream(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no encryption specified for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	
}`,
			mustIncludeResultCode: rules.AWSUnencryptedKinesisStream,
		},
		{
			name: "check encryption disabled for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "NONE"
}`,
			mustIncludeResultCode: rules.AWSUnencryptedKinesisStream,
		},
		{
			name: "check no encryption key id specified for aws_kinesis_stream",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
}`,
			mustIncludeResultCode: rules.AWSUnencryptedKinesisStream,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
resource "aws_kinesis_stream" "test_stream" {
	encryption_type = "KMS"
	kms_key_id = "my/key"
}`,
			mustExcludeResultCode: rules.AWSUnencryptedKinesisStream,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
