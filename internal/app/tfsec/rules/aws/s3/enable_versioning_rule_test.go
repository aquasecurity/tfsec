package s3

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSS3DataShouldBeVersioned(t *testing.T) {
	expectedCode := "aws-s3-enable-versioning"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule fails if bucket has no versioning block",
			source: `
resource "aws_s3_bucket" "bad_example" {

}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule passes if versioning block present and enabled",
			source: `
resource "aws_s3_bucket" "good_example" {
	versioning {
		
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
