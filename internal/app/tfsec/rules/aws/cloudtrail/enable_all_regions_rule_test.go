package cloudtrail
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSCloudtrailEnabledInAllRegions(t *testing.T) {
// 	expectedCode := "aws-cloudtrail-enable-all-regions"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "Test cloudtrail not configured for multi region use",
// 			source: `
// resource "aws_cloudtrail" "bad_example" {
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
// 			name: "Test multiregion set to false fails",
// 			source: `
// resource "aws_cloudtrail" "bad_example" {
//   is_multi_region_trail = false
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
// 			name: "Test multi region correctly configured",
// 			source: `
// resource "aws_cloudtrail" "good_example" {
//   is_multi_region_trail = true
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
