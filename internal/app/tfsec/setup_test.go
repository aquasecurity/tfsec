package tfsec

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const exampleCheckCode scanner.RuleID = "EXA001"

var excludedChecksList []string

func TestMain(t *testing.M) {

	scanner.RegisterCheck(scanner.Check{
		Code:           exampleCheckCode,
		RequiredLabels: []string{"problem"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult("example problem", block.Range(), scanner.SeverityError),
			}
		},
	})

	os.Exit(t.Run())
}

func scanSource(source string) []scanner.Result {
	blocks := createBlocksFromSource(source)
	return scanner.New().Scan(blocks, excludedChecksList)
}

func createBlocksFromSource(source string) []*parser.Block {
	path := createTestFile("test.tf", source)
	blocks, err := parser.New().ParseDirectory(filepath.Dir(path), nil, "")
	if err != nil {
		panic(err)
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

func assertCheckCode(t *testing.T, includeCode scanner.RuleID, excludeCode scanner.RuleID, results []scanner.Result) {

	var foundInclude bool
	var foundExclude bool

	for _, result := range results {
		if result.RuleID == excludeCode {
			foundExclude = true
		}
		if result.RuleID == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("result with code '%s' was found but should not have been", excludeCode))
	if includeCode != scanner.RuleID("") {
		assert.True(t, foundInclude, fmt.Sprintf("result with code '%s' was not found but should have been", includeCode))
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
