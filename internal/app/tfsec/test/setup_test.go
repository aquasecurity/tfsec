package test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const exampleCheckCode = "EXA001"

var excludedChecksList []string

func TestMain(t *testing.M) {

	scanner.RegisterCheckRule(rule.Rule{
		ID: exampleCheckCode,
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
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.GetAttribute("bad") != nil {
				set.Add(
					result.New(resourceBlock).WithDescription("example problem").WithRange(resourceBlock.Range()).WithSeverity(severity.Error),
				)
			}
		},
	})

	os.Exit(t.Run())
}

func scanHCL(source string, t *testing.T) []result.Result {
	blocks := createBlocksFromSource(source, ".tf", t)
	return scanner.New(scanner.OptionExcludeRules(excludedChecksList)).Scan(blocks)
}

func scanJSON(source string, t *testing.T) []result.Result {
	blocks := createBlocksFromSource(source, ".tf.json", t)
	return scanner.New(scanner.OptionExcludeRules(excludedChecksList)).Scan(blocks)
}

func createBlocksFromSource(source string, ext string, t *testing.T) []block.Block {
	path := createTestFile("test"+ext, source)
	blocks, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return blocks
}

func createTestFile(filename, contents string) string {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		panic(err)
	}
	path := filepath.Join(dir, filename)
	if err := ioutil.WriteFile(path, []byte(contents), 0755); err != nil {
		panic(err)
	}
	return path
}

func assertCheckCode(t *testing.T, includeCode string, excludeCode string, results []result.Result) {

	var foundInclude bool
	var foundExclude bool

	var excludeText string

	for _, res := range results {
		if res.RuleID == excludeCode {
			foundExclude = true
			excludeText = res.Description
		}
		if res.RuleID == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been: %s", excludeCode, excludeText))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been", includeCode))
	}
}

func createTestFileWithModule(contents string, moduleContents string) string {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		panic(err)
	}

	rootPath := filepath.Join(dir, "main")
	modulePath := filepath.Join(dir, "module")

	if err := os.Mkdir(rootPath, 0755); err != nil {
		panic(err)
	}

	if err := os.Mkdir(modulePath, 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(rootPath, "main.tf"), []byte(contents), 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(modulePath, "main.tf"), []byte(moduleContents), 0755); err != nil {
		panic(err)
	}

	return rootPath
}
