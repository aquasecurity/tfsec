package kinesis
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSUnencryptedKinesisStream(t *testing.T) {
// 	expectedCode := "aws-kinesis-enable-in-transit-encryption"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check no encryption specified for aws_kinesis_stream",
// 			source: `
// resource "aws_kinesis_stream" "test_stream" {
// 	
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check encryption disabled for aws_kinesis_stream",
// 			source: `
// resource "aws_kinesis_stream" "test_stream" {
// 	encryption_type = "NONE"
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check no encryption key id specified for aws_kinesis_stream",
// 			source: `
// resource "aws_kinesis_stream" "test_stream" {
// 	encryption_type = "KMS"
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check encryption key id specified for aws_sqs_queue",
// 			source: `
// resource "aws_kinesis_stream" "test_stream" {
// 	encryption_type = "KMS"
// 	kms_key_id = "my/key"
// }`,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
