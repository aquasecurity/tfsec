package sqs

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSUnencryptedSQSQueue(t *testing.T) {
	expectedCode := "aws-sqs-enable-queue-encryption"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check blank encryption key id specified for aws_sqs_queue",
			source: `
 resource "aws_sqs_queue" "my-queue" {
 	kms_master_key_id = ""
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check encryption key id specified for aws_sqs_queue",
			source: `
 resource "aws_sqs_queue" "my-queue" {
 	kms_master_key_id = "/blah"
 }`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
