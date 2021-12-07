package cloudtrail
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSCloudtrailEncryptedAtRest(t *testing.T) {
// 	expectedCode := "aws-cloudtrail-enable-at-rest-encryption"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{{
// 		name: "Test check fails when missing kms id",
// 		source: `
// resource "aws_cloudtrail" "bad_example" {
//   is_multi_region_trail = true
//   enable_log_file_validation = true
// 
//   event_selector {
//     read_write_type           = "All"
//     include_management_events = true
// 
//     data_resource {
//       type = "AWS::S3::Object"
//       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
//     }
//   }
// }
// `,
// 		mustIncludeResultCode: expectedCode,
// 	},
// 		{
// 			name: "Test check fails when kms_key_id present but empty",
// 			source: `
// resource "aws_cloudtrail" "bad_example" {
//   is_multi_region_trail = true
//   enable_log_file_validation = true
//   kms_key_id = ""
// 
//   event_selector {
//     read_write_type           = "All"
//     include_management_events = true
// 
//     data_resource {
//       type = "AWS::S3::Object"
//       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
//     }
//   }
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Test check passes when kms_key_id present and populated",
// 			source: `
// resource "aws_cloudtrail" "good_example" {
//   is_multi_region_trail = true
//   enable_log_file_validation = true
//   kms_key_id = var.kms_id
// 
//   event_selector {
//     read_write_type           = "All"
//     include_management_events = true
// 
//     data_resource {
//       type = "AWS::S3::Object"
//       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
//     }
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
