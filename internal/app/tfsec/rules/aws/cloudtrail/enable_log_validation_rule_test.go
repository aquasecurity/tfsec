package cloudtrail

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCloudtrailLogValidationEnabled(t *testing.T) {
	expectedCode := "aws-cloudtrail-enable-log-validation"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Test log file validation is not specified",
			source: `
 resource "aws_cloudtrail" "bad_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Test log file validation is specified but not true",
			source: `
 resource "aws_cloudtrail" "bad_example" {
   is_multi_region_trail = true
   enable_log_file_validation = false 
   
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Test enable log validation is configured correctly",
			source: `
 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   enable_log_file_validation = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 `,
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
