package rule

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil/filesystem"
	"github.com/stretchr/testify/assert"
)

func TestRequiredSourcesMatch(t *testing.T) {

	var moduleSource string = `resource "simple" "very" {
		something = "1"
	}`

	var tests = []struct {
		name       string
		rule       Rule
		source     string
		modulePath string
		expected   bool
	}{
		{
			name: "check false evaluation when module not in required type",
			rule: Rule{
				RequiredTypes:  []string{"data"},
				RequiredLabels: []string{"custom_module"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "module",
			source: `
module "custom_module" {
	source = "../module"
}
`,
			expected: false,
		},
		{
			name: "check false evaluation when requiredLabels doesn't match",
			rule: Rule{
				RequiredTypes:  []string{"module"},
				RequiredLabels: []string{"dont_match"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "module",
			source: `
module "custom_module" {
	source = "../module"
}
`,
			expected: false,
		},
		{
			name: "check true evaluation when requiredTypes and requiredLabels match",
			rule: Rule{
				RequiredTypes:  []string{"module"},
				RequiredLabels: []string{"*"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "module",
			source: `
module "custom_module" {
	source = "../module"
}
`,
			expected: true,
		},
		{
			name: "check false evaluation when requiredSources does not match",
			rule: Rule{
				RequiredTypes:   []string{"module"},
				RequiredLabels:  []string{"*"},
				RequiredSources: []string{"path_doesnt_match"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "module",
			source: `
module "custom_module" {
	source = "../module"
}
`,
			expected: false,
		},
		{
			name: "check true evaluation when requiredSources does match",
			rule: Rule{
				RequiredTypes:   []string{"module"},
				RequiredLabels:  []string{"*"},
				RequiredSources: []string{"github.com/hashicorp/example"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "module",
			source: `
module "custom_module" {
	source = "github.com/hashicorp/example"
}
`,
			expected: true,
		},
		{
			name: "check true evaluation when requiredSources does match with wildcard prefix",
			rule: Rule{
				RequiredTypes:   []string{"module"},
				RequiredLabels:  []string{"*"},
				RequiredSources: []string{"*two/three"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "one/two/three",
			source: `
module "custom_module" {
	source = "../one/two/three"
}
`,
			expected: true,
		},
		{
			name: "check true evaluation when requiredSources does match relative path match",
			rule: Rule{
				RequiredTypes:   []string{"module"},
				RequiredLabels:  []string{"*"},
				RequiredSources: []string{"one/two/three"},
				CheckTerraform: func(block.Block, block.Module) rules.Results {
					return nil
				},
			},
			modulePath: "one/two/three",
			source: `
module "custom_module" {
	source = "../one/two/three"
}
`,
			expected: true,
		},
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			fs, err := filesystem.New()
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()

			if err := fs.WriteTextFile("src/main.tf", test.source); err != nil {
				t.Fatal(err)
			}

			if err := fs.WriteTextFile(filepath.Join(test.modulePath, "main.tf"), moduleSource); err != nil {
				t.Fatal(err)
			}

			modules, err := parser.New(fs.RealPath("src/"), parser.OptionStopOnHCLError()).ParseDirectory()
			if err != nil {
				t.Fatal(err)
			}

			os.Chdir(fs.RealPath("/")) // change directory for relative path tests to work
			result := test.rule.isRuleRequiredForBlock(modules[0].GetBlocks()[0])
			assert.Equal(t, test.expected, result, "`IsRuleRequiredForBlock` match function evaluating incorrectly for requiredSources test.")
		})
	}
	os.Chdir(wd)
}
