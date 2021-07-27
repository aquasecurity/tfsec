package main

const checkTemplate = `package {{ .Package}}

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
		Service:   "{{ .Service}}",
		ShortCode: "{{ .ShortCode}}",
		Documentation: rule.RuleDocumentation{
			Summary:     "{{.Summary}}",
			Explanation:` + "`" + `	` + "`" + `,
			Impact:      "{{.Impact}}",
			Resolution:  "{{.Resolution}}",
			BadExample: []string{  ` + "`" + `
			// bad example code here
			` + "`" + `},
			GoodExample: []string{ ` + "`" + `
			// good example code here
			` + "`" + `},
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

const checkTestTemplate = `package {{ .Package}}

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

package s3

import (
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_{{.CheckName}}_FailureExamples(t *testing.T) {
	expectedCode := "{{ .FullCode}}"

	check, err := scanner.GetRuleById(expectedCode)
	if err != nil {
		t.FailNow()
	}
	for i, badExample := range check.Documentation.BadExample {
		t.Logf("Running bad example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(badExample) == "" {
			t.Fatalf("bad example code not provided for %s", check.ID())
		}
		defer func() {
			if err := recover(); err != nil {
				t.Fatalf("Scan (bad) failed: %s", err)
			}
		}()
		results := testutil.ScanHCL(badExample, t)
		testutil.AssertCheckCode(t, check.ID(), "", results)
	}
}

func Test_{{.CheckName}}_SuccessExamples(t *testing.T) {
	expectedCode := "{{ .FullCode}}"

	check, err := scanner.GetRuleById(expectedCode)
	if err != nil {
		t.FailNow()
	}
	for i, example := range check.Documentation.GoodExample {
		t.Logf("Running good example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(example) == "" {
			t.Fatalf("good example code not provided for %s", check.ID())
		}
		defer func() {
			if err := recover(); err != nil {
				t.Fatalf("Scan (good) failed: %s", err)
			}
		}()
		results := testutil.ScanHCL(example, t)
		testutil.AssertCheckCode(t, "", check.ID(), results)
	}
}
`
