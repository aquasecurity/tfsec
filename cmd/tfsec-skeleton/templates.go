package main

const checkTemplate = `package checks

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/tfsec/tfsec/pkg/rule"
)

const {{.CheckName}} = "{{.Provider | ToUpper }}{{ .ID}}"
const {{.CheckName}}Description = "{{.Summary}}"
const {{.CheckName}}Impact = "{{.Impact}}"
const {{.CheckName}}Resolution = "{{.Resolution}}"
const {{.CheckName}}Explanation = ` + "`" + `

` + "`" + `
const {{.CheckName}}BadExample = ` + "`" + `
resource "" "bad_example" {

}
` + "`" + `
const {{.CheckName}}GoodExample = ` + "`" + `
resource "" "good_example" {

}
` + "`" + `

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: {{.CheckName}},
		Documentation: scanner.CheckDocumentation{
			Summary:     {{.CheckName}}Description,
			Explanation: {{.CheckName}}Explanation,
			Impact:      {{.CheckName}}Impact,
			Resolution:  {{.CheckName}}Resolution,
			BadExample:  {{.CheckName}}BadExample,
			GoodExample: {{.CheckName}}GoodExample,
			Links: []string{
				
			},
		},
		Provider:       scanner.{{.ProviderLongName}}Provider,
		RequiredTypes:  []string{{.RequiredTypes}},
		RequiredLabels: []string{{.RequiredLabels}},
		CheckFunc: func(block *parser.Block, _ *scanner.Context) []scanner.Result {
				
			// function contents here

			return nil
		},
	})
}
`

const checkTestTemplate = `package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_{{.CheckName}}(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
		t.Check(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
`
