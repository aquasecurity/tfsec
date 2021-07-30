package cloudwatch

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCloudWatchLogGroupsCMKEncrypted(t *testing.T) {
	expectedCode := "aws-cloudwatch-log-group-customer-key"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "cloudwatch with cmk passes check",
			source: `
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.id
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
