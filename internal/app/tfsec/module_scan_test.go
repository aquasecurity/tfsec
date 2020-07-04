package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

func Test_ProblemInModule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		moduleSource          string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check problem in module",
			source: `
module "something" {
	source = "../module"
}
`,
			moduleSource: `
resource "problem" "uhoh" {}
`,
			mustIncludeResultCode: exampleCheckCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := createTestFileWithModule(test.source, test.moduleSource)
			blocks, err := parser.New().ParseDirectory(path, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			results := scanner.New().Scan(blocks, excludedChecksList)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
