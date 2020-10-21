package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_ProblemInModule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		moduleSource          string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check problem in module",
			source: `
module "something" {
	source = "../module"
}
`,
			moduleSource: `
resource "problem" "uhoh" {
	bad = "1"
}
`,
			mustIncludeResultCode: exampleCheckCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := createTestFileWithModule(test.source, test.moduleSource)
			blocks, err := parser.New(path, "").ParseDirectory()
			if err != nil {
				t.Fatal(err)
			}
			results := scanner.New().Scan(blocks, excludedChecksList)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
