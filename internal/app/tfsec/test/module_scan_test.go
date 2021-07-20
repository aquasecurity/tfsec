package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func Test_ProblemInModule(t *testing.T) {

	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "EXA001",
		Provider:  provider.AWSProvider,
		Service:   "service",
		ShortCode: "abc",
		Documentation: rule.RuleDocumentation{
			Summary:     "A stupid example check for a test.",
			Impact:      "You will look stupid",
			Resolution:  "Don't do stupid stuff",
			Explanation: "Bad should not be set.",
			BadExample: `
resource "problem" "x" {
	bad = "1"
}
`,
			GoodExample: `
resource "problem" "x" {
	
}
`,
			Links: nil,
		},
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"problem"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.GetAttribute("bad") != nil {
				set.Add(
					result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()),
				)
			}
		},
	})

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
			mustIncludeResultCode: "aws-service-abc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := testutil.CreateTestFileWithModule(test.source, test.moduleSource)
			blocks, err := parser.New(path, parser.OptionStopOnHCLError()).ParseDirectory()
			if err != nil {
				t.Fatal(err)
			}
			results := scanner.New(scanner.OptionIgnoreCheckErrors(false)).Scan(blocks)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
