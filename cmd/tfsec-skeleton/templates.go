package main

const checkTemplate = `package {{ .Service}}

import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)


func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service: "{{ .Service}}",
		ShortCode: "{{ .ShortCode}}",
		Documentation: rule.RuleDocumentation{
			Summary:     "{{.Summary}}",
			Explanation:` + "`" + `	` + "`" + `,
			Impact:      "{{.Impact}}",
			Resolution:  "{{.Resolution}}",
			BadExample:  ` + "`" + `
			// bad example code here
			` + "`" + `,
			GoodExample: ` + "`" + `
			// good example code here
			` + "`" + `,
			Links: []string{
				
			},
		},
		Provider:       provider.{{.ProviderLongName}}Provider,
		RequiredTypes:  []string{{.RequiredTypes}},
		RequiredLabels: []string{{.RequiredLabels}},
		DefaultSeverity: severity.Medium, 
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context){
				
			// function contents here

		},
	})
}
`

const checkTestTemplate = `package {{ .Service}}

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_{{.CheckName}}(t *testing.T) {
	expectedCode := "{{ .FullCode}}"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "TODO: add test name",
			source: ` + "`" + `
	// good test
` + "`" + `,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
`
