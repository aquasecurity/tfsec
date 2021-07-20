package ssm

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSSecretsManagerSecretEncryption(t *testing.T) {
	expectedCode := "aws-ssm-secret-use-customer-key"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "secret without specified CMK fails check",
			source: `
				resource "aws_secretsmanager_secret" "bad_example" {
				  name       = "lambda_password"
				}
				`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Secret using default CMK fails check",
			source: `
		data "aws_kms_key" "by_alias" {
		  key_id = "alias/aws/secretsmanager"
		}

		resource "aws_secretsmanager_secret" "bad_example" {
		  name       = "lambda_password"
		  kms_key_id = data.aws_kms_key.by_alias.arn
		}
		`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Secret with customer control CMK passes check",
			source: `
					data "aws_kms_key" "by_alias" {
						key_id = "alias/aws/secretsmanager"
					  }

		resource "aws_secretsmanager_secret" "good_example" {
		  name       = "lambda_password"
		  kms_key_id = aws_kms_key.secrets.arn
		}
		`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Secret with customer control CMK passes check",
			source: `
data "aws_kms_key" "ours_by_alias" {
  key_id = "alias/ourkeys/lambda_secret"
}

resource "aws_secretsmanager_secret" "good_example" {
  name       = "lambda_password"
  kms_key_id = data.aws_kms_key.ours_by_alias.arn
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
