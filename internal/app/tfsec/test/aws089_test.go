package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSCloudWatchLogGroupsCMKEncrypted(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "cloudwatch without cmk fails check",
			source: `
resource "aws_cloudwatch_log_group" "bad_exampe" {
	name = "bad_example"
}
`,
			mustIncludeResultCode: rules.AWSCloudWatchLogGroupsCMKEncrypted,
		},
		{
			name: "cloudwatch with cmk passes check",
			source: `
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.id
}
`,
			mustExcludeResultCode: rules.AWSCloudWatchLogGroupsCMKEncrypted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
