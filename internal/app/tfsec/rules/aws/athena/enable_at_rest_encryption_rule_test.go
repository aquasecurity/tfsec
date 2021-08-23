package athena
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSEnsureAthenaDbEncrypted(t *testing.T) {
// 	expectedCode := "aws-athena-enable-at-rest-encryption"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "test athena database without encryption configuration",
// 			source: `
// resource "aws_athena_database" "bad_example" {
//   name   = "database_name"
//   bucket = aws_s3_bucket.hoge.bucket
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "test athena workgroup without encryption configuration",
// 			source: `
// resource "aws_athena_workgroup" "bad_example" {
//   name = "example"
// 
//   configuration {
//     enforce_workgroup_configuration    = true
//     publish_cloudwatch_metrics_enabled = true
// 
//     result_configuration {
//       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
//     }
//   }
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "test athena database with encryption configuration",
// 			source: `
// resource "aws_athena_database" "good_example" {
//   name   = "database_name"
//   bucket = aws_s3_bucket.hoge.bucket
// 
//   encryption_configuration {
//      encryption_option = "SSE_KMS"
//      kms_key_arn       = aws_kms_key.example.arn
//  }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "test athena workgroup with encryption configuration in results configuration",
// 			source: `
// resource "aws_athena_workgroup" "good_example" {
//   name = "example"
// 
//   configuration {
//     enforce_workgroup_configuration    = true
//     publish_cloudwatch_metrics_enabled = true
// 
//     result_configuration {
//       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
// 
//       encryption_configuration {
//         encryption_option = "SSE_KMS"
//         kms_key_arn       = aws_kms_key.example.arn
//       }
//     }
//   }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "test athena workgroup with no results configuration",
// 			source: `
// resource "aws_athena_workgroup" "good_example" {
//   name = "example"
// 
//   configuration {
//     enforce_workgroup_configuration    = true
//     publish_cloudwatch_metrics_enabled = true
//   }
// }
// `,
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
