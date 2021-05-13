package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSSecretsManagerSecretEncryption(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "secret without specified CMK fails check",
			source: `
				resource "aws_secretsmanager_secret" "bad_example" {
				  name       = "lambda_password"
				}
				`,
			mustIncludeResultCode: checks.AWSSecretsManagerSecretEncryption,
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
			mustIncludeResultCode: checks.AWSSecretsManagerSecretEncryption,
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
			mustExcludeResultCode: checks.AWSSecretsManagerSecretEncryption,
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
			mustExcludeResultCode: checks.AWSSecretsManagerSecretEncryption,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
