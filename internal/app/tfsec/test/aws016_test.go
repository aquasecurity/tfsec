package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedSNSTopic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check no encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	
}`,
			mustIncludeResultCode: checks.AWSUnencryptedSNSTopic,
		},
		{
			name: "check blank encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	kms_master_key_id = ""
}`,
			mustIncludeResultCode: checks.AWSUnencryptedSNSTopic,
		},
		{
			name: "check encryption key id specified for aws_sns_topic",
			source: `
resource "aws_sns_topic" "my-topic" {
	kms_master_key_id = "/blah"
}`,
			mustExcludeResultCode: checks.AWSUnencryptedSNSTopic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
