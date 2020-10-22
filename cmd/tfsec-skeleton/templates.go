package main

const checkTemplate = `package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const {{.CheckName}} scanner.RuleCode = "{{.Provider | ToUpper }}{{ .Code}}"
const {{.CheckName}}Description scanner.RuleSummary = "{{.Summary}}"
const {{.CheckName}}Explanation = ` + "`" + `

` + "`" + `
const {{.CheckName}}BadExample = ` + "`" + `
resource "" "my-" {

}
` + "`" + `
const {{.CheckName}}GoodExample = ` + "`" + `
resource "" "my-" {

}
` + "`" + `

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: {{.CheckName}},
		Documentation: scanner.CheckDocumentation{
			Summary:     {{.CheckName}}Description,
			Explanation: {{.CheckName}}Explanation,
			BadExample:  {{.CheckName}}BadExample,
			GoodExample: {{.CheckName}}GoodExample,
			Links: []string{
				
			},
		},
		Provider:       scanner.{{.ProviderLongName}}Provider,
		RequiredTypes:  []string{{.RequiredTypes}},
		RequiredLabels: []string{{.RequiredLabels}},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
				
			// function contents here

			return nil
		},
	})
}
`

const checkTestTemplate = `package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_{{.CheckName}}(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "TODO: add test name",
			source: ` + "`" + `
	// bad test
` + "`" + `,
			mustIncludeResultCode: checks.{{.CheckName}},
		},
		{
			name: "TODO: add test name",
			source: ` + "`" + `
	// good test
` + "`" + `,
			mustExcludeResultCode: checks.{{.CheckName}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
`
