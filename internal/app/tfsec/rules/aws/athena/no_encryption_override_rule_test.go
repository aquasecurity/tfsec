package athena

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSAthenaWorkgroupEnforceConfiguration(t *testing.T) {
	expectedCode := "aws-athena-no-encryption-override"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "test athena workgroup with configuration but enforce set to false",
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "test athena workgroup with no configuration at all",
			source: `resource "aws_athena_workgroup" "good_example" {
  name = "example"

}
`,
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
