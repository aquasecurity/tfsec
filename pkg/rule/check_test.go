package rule

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/pkg/result"
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
				CheckFunc:      func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:      func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:      func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:       func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:       func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:       func(result.Set, block.Block, *hclcontext.Context) {},
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
				CheckFunc:       func(result.Set, block.Block, *hclcontext.Context) {},
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block, testDir := createBlocksFromSourceWithModule(test.source, test.modulePath, moduleSource)
			os.Chdir(testDir) // change directory for relative path tests to work
			result := IsRuleRequiredForBlock(&test.rule, block[0])
			assert.Equal(t, test.expected, result, "`IsRuleRequiredForBlock` match function evaluating incorrectly for requiredSources test.")
		})
	}
}

func createBlocksFromSourceWithModule(contents string, moduleSubDir string, moduleContents string) ([]block.Block, string) {
	dir := createTestFileWithModuleSubDir(contents, moduleSubDir, moduleContents)
	blocks, err := parser.New(dir, parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		panic(err)
	}
	return blocks, dir
}

func createTestFileWithModuleSubDir(contents string, moduleSubDir string, moduleContents string) string {
	var tempDir string
	if runtime.GOOS == "darwin" {
		// osx tmpdir path is a symlink to /private/var/... which messes with tests
		osxTmpDir := os.TempDir()
		if strings.HasPrefix(osxTmpDir, "/var") {
			tempDir = filepath.Join("/private/", osxTmpDir)
		}
	}

	dir, err := ioutil.TempDir(tempDir, "tfsec-testing-")
	if err != nil {
		panic(err)
	}

	rootPath := filepath.Join(dir, "main")
	modulePath := filepath.Join(dir, moduleSubDir)

	if err := os.Mkdir(rootPath, 0755); err != nil {
		panic(err)
	}

	if err := os.MkdirAll(modulePath, 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(rootPath, "main.tf"), []byte(contents), 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(modulePath, "main.tf"), []byte(moduleContents), 0755); err != nil {
		panic(err)
	}

	return dir
}
