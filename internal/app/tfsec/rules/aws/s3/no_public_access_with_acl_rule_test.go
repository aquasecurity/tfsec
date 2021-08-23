package s3
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSACL(t *testing.T) {
// 	expectedCode := "aws-s3-no-public-access-with-acl"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check aws_s3_bucket with acl=public-read",
// 			source: `
// resource "aws_s3_bucket" "my-bucket" {
// 	acl = "public-read"
// 	logging {}
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_s3_bucket with acl=public-read-write",
// 			source: `
// resource "aws_s3_bucket" "my-bucket" {
// 	acl = "public-read-write"
// 	logging {}
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_s3_bucket with acl=website",
// 			source: `
// resource "aws_s3_bucket" "my-bucket" {
// 	acl = "website"
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_s3_bucket with acl=private",
// 			source: `
// resource "aws_s3_bucket" "my-bucket" {
// 	acl = "private"
// }`,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_s3_bucket with acl not set",
// 			source: `
// resource "aws_s3_bucket" "my-bucket" {
// 
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
