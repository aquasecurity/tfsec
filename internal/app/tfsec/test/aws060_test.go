package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSAthenaWorkgroupEnforceConfiguration(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "test athena workgroup with configration but enforce set to false",
			source: `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = false
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}`,
			mustIncludeResultCode: checks.AWSAthenaWorkgroupEnforceConfiguration,
		},
		{
			name: "test athena workgroup with no configuration at all",
			source: `resource "aws_athena_workgroup" "good_example" {
  name = "example"

}
`,
			mustIncludeResultCode: checks.AWSAthenaWorkgroupEnforceConfiguration,
		},
		{
			name: "test athena workgoup with configuration and enforce true",
			source: `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}
`,
			mustExcludeResultCode: checks.AWSAthenaWorkgroupEnforceConfiguration,
		},
		{
			name: "test athena workgoup with configuration and enforce not set (default true)",
			source: `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}
`,
			mustExcludeResultCode: checks.AWSAthenaWorkgroupEnforceConfiguration,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
