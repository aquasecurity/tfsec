package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSS3DataShouldBeVersioned(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check fails if bucket has no versioning block",
			source: `
resource "aws_s3_bucket" "bad_example" {

}
`,
			mustIncludeResultCode: checks.AWSS3DataShouldBeVersioned,
		},
		{
			name: "Check passes if versioning block present and enabled",
			source: `
resource "aws_s3_bucket" "good_example" {
	versioning {
		
	}
}
`,
			mustExcludeResultCode: checks.AWSS3DataShouldBeVersioned,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
