package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSEnsureAthenaDbEncrypted(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "test athena database without encryption configuration",
			source: `
resource "aws_athena_database" "bad_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket
}
`,
			mustIncludeResultCode: rules.AWSEnsureAthenaDbEncrypted,
		},
		{
			name: "test athena workgroup without encryption configuration",
			source: `
resource "aws_athena_workgroup" "bad_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
    }
  }
}
`,
			mustIncludeResultCode: rules.AWSEnsureAthenaDbEncrypted,
		},
		{
			name: "test athena database with encryption configuration",
			source: `
resource "aws_athena_database" "good_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket

  encryption_configuration {
     encryption_option = "SSE_KMS"
     kms_key_arn       = aws_kms_key.example.arn
 }
}
`,
			mustExcludeResultCode: rules.AWSEnsureAthenaDbEncrypted,
		},
		{
			name: "test athena workgroup with encryption configuration in results configuration",
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
			mustExcludeResultCode: rules.AWSEnsureAthenaDbEncrypted,
		},
		{
			name: "test athena workgroup with no results configuration",
			source: `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
  }
}
`,
			mustExcludeResultCode: rules.AWSEnsureAthenaDbEncrypted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
