package main

const checkTemplate = `package rules

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)


const {{.CheckName}} = "{{.Provider | ToUpper }}{{ .ID}}"
const {{.CheckName}}Description = "{{.Summary}}"
const {{.CheckName}}Impact = "{{.Impact}}"
const {{.CheckName}}Resolution = "{{.Resolution}}"
const {{.CheckName}}Explanation = ` + "`" + `

` + "`" + `
const {{.CheckName}}BadExample = ` + "`" + `
// bad example code here
` + "`" + `
const {{.CheckName}}GoodExample = ` + "`" + `
// good example code here
` + "`" + `

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: {{.CheckName}},
		Documentation: rule.RuleDocumentation{
			Summary:     {{.CheckName}}Description,
			Explanation: {{.CheckName}}Explanation,
			Impact:      {{.CheckName}}Impact,
			Resolution:  {{.CheckName}}Resolution,
			BadExample:  {{.CheckName}}BadExample,
			GoodExample: {{.CheckName}}GoodExample,
			Links: []string{
				
			},
		},
		Provider:       provider.{{.ProviderLongName}}Provider,
		RequiredTypes:  []string{{.RequiredTypes}},
		RequiredLabels: []string{{.RequiredLabels}},
		DefaultSeverity: severity.Warning, 
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context){
				
			// function contents here

		},
	})
}
`

const checkTestTemplate = `package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
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
			mustIncludeResultCode: rules.{{.CheckName}},
		},
		{
			name: "TODO: add test name",
			source: ` + "`" + `
	// good test
` + "`" + `,
			mustExcludeResultCode: rules.{{.CheckName}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
`
