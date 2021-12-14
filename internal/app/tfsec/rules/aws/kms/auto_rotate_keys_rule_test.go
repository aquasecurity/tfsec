package kms
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSNoKmsKeyAutoRotate(t *testing.T) {
 	expectedCode := "aws-kms-auto-rotate-keys"
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name:                  "check KMS Key with auto-rotation not set",
 			source:                `resource "aws_kms_key" "kms_key" {}`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check KMS Key with auto-rotation disabled",
 			source: `
 resource "aws_kms_key" "kms_key" {
 	enable_key_rotation = false
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check KMS Key with auto-rotation enabled",
 			source: `
 resource "aws_kms_key" "kms_key" {
 	enable_key_rotation = true
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check SIGN_VERIFY KMS Key with auto-rotation disabled",
 			source: `
 resource "aws_kms_key" "kms_key" {
 	key_usage = "SIGN_VERIFY"
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
