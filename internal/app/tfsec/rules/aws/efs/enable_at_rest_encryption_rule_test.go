package efs
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSEfsEncryptionNotEnabled(t *testing.T) {
 	expectedCode := "aws-efs-enable-at-rest-encryption"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name:                  "check if EFS Encryption is disabled",
 			source:                `resource "aws_efs_file_system" "foo" {}`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check if EFS Encryption is set to false",
 			source: `
 resource "aws_efs_file_system" "foo" {
   name                 = "bar"
   encrypted = false
   kms_key_id = ""
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "Encryption key is provided",
 			source: `
 resource "aws_efs_file_system" "foo" {
   name                 = "bar"
   encrypted = true
   kms_key_id = "my_encryption_key"
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
