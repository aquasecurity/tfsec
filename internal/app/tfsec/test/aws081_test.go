package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSDAXEncryptedAtRest(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule should not pass when no SSE block at all",
			source: `
resource "aws_dax_cluster" "bad_example" {
	// no server side encryption at all
}
`,
			mustIncludeResultCode: rules.AWSDAXEncryptedAtRest,
		}, {
			name: "Rule should not pass when SSE block empty",
			source: `
resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		// empty server side encryption config
	}
}
`,
			mustIncludeResultCode: rules.AWSDAXEncryptedAtRest,
		},
		{
			name: "Rule should not pass when SSE disabled",
			source: `
resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		enabled = false // disabled server side encryption
	}
}
`,
			mustIncludeResultCode: rules.AWSDAXEncryptedAtRest,
		},
		{
			name: "Rule should pass when SSE is enabled",
			source: `
resource "aws_dax_cluster" "good_example" {
	// other DAX config

	server_side_encryption {
		enabled = true // enabled server side encryption
	}
}
`,
			mustExcludeResultCode: rules.AWSDAXEncryptedAtRest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
