package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSDAXEncryptedAtRest(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "TODO: add test name",
			source: `
	// bad test
`,
			mustIncludeResultCode: checks.AWSDAXEncryptedAtRest,
		},
		{
			name: "TODO: add test name",
			source: `
	// good test
`,
			mustExcludeResultCode: checks.AWSDAXEncryptedAtRest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
