package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSCloudtrailEncryptedAtRest(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{		{
		name: "Test check fails when missing kms id",
		source: `
resource "aws_cloudtrail" "bad_example" {
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
		mustIncludeResultCode: checks.AWSCloudtrailEncryptedAtRest,
	},
		{
			name: "Test check fails when kms_key_id present but empty",
			source: `
resource "aws_cloudtrail" "bad_example" {
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = ""

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
			mustIncludeResultCode: checks.AWSCloudtrailEncryptedAtRest,
		},
		{
			name: "Test check passes when kms_key_id present and populated",
			source: `
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = var.kms_id

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
			mustExcludeResultCode: checks.AWSCloudtrailEncryptedAtRest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
