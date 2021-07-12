package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedSNSTopic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	
}`,
			mustIncludeResultCode: rules.AWSUnencryptedSNSTopic,
		},
		{
			name: "check with default encryption key id specified for aws_sns_topic fails check",
			source: `
data "aws_kms_key" "by_alias" {
  key_id = "alias/aws/sns"
}

resource "aws_sns_topic" "test" {
  name              = "sns_ecnrypted"
  kms_master_key_id = data.aws_kms_key.by_alias.arn
}`,
			mustIncludeResultCode: rules.AWSUnencryptedSNSTopic,
		},
		{
			name: "check blank encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	kms_master_key_id = ""
}`,
			mustIncludeResultCode: rules.AWSUnencryptedSNSTopic,
		},
		{
			name: "check encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	kms_master_key_id = "/blah"
}`,
			mustExcludeResultCode: rules.AWSUnencryptedSNSTopic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
