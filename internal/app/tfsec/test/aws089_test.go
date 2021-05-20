package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSCloudWatchLogGroupsCMKEncrypted(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "cloudwatch without cmk fails check",
			source: `
resource "aws_cloudwatch_log_group" "bad_exampe" {
	name = "bad_example"
}
`,
			mustIncludeResultCode: checks.AWSCloudWatchLogGroupsCMKEncrypted,
		},
		{
			name: "cloudwatch with cmk passes check",
			source: `
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.id
}
`,
			mustExcludeResultCode: checks.AWSCloudWatchLogGroupsCMKEncrypted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
