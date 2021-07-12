package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func Test_ProblemInModule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		moduleSource          string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			blocks, err := parser.New(path, parser.OptionStopOnHCLError()).ParseDirectory()
			if err != nil {
				t.Fatal(err)
			}
			results := scanner.New(scanner.OptionExcludeRules(excludedChecksList)).Scan(blocks)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
