package sns
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSUnencryptedSNSTopic(t *testing.T) {
 	expectedCode := "aws-sns-enable-topic-encryption"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check no encryption key id specified for aws_sns_topic",
 			source: `
 resource "aws_sns_topic" "my-topic" {
 	
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check with default encryption key id specified for aws_sns_topic fails check",
 			source: `
 data "aws_kms_key" "by_alias" {
   key_id = "alias/aws/sns"
 }
 
 resource "aws_sns_topic" "test" {
   name              = "sns_ecnrypted"
   kms_master_key_id = data.aws_kms_key.by_alias.arn
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check blank encryption key id specified for aws_sns_topic",
 			source: `
 resource "aws_sns_topic" "my-topic" {
 	kms_master_key_id = ""
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check encryption key id specified for aws_sns_topic",
 			source: `
 resource "aws_sns_topic" "my-topic" {
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
