package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSS3DataShouldBeVersioned(t *testing.T) {

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
			mustIncludeResultCode: rules.AWSS3DataShouldBeVersioned,
		},
		{
			name: "Rule passes if versioning block present and enabled",
			source: `
resource "aws_s3_bucket" "good_example" {
	versioning {
		
	}
}
`,
			mustExcludeResultCode: rules.AWSS3DataShouldBeVersioned,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
