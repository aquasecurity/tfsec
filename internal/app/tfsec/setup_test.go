package tfsec

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

const exampleCheckCode checks.Code = "EXA001"

func TestMain(t *testing.M) {

	checks.RegisterCheck(checks.Check{
		RequiredLabels: []string{"problem"},
		CheckFunc: func(block *parser.Block) []checks.Result {
			return []checks.Result{
				checks.NewResult(exampleCheckCode, "example problem", block.Range()),
			}
		},
	})

	os.Exit(t.Run())
}

func scanSource(source string) []checks.Result {
	blocks := createBlocksFromSource(source)
	return scanner.New().Scan(blocks)
}

func createBlocksFromSource(source string) []*parser.Block {
	path := createTestFile("test.tf", source)
	blocks, err := parser.New().ParseDirectory(filepath.Dir(path))
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

func assertCheckCode(t *testing.T, includeCode checks.Code, excludeCode checks.Code, results []checks.Result) {

	var foundInclude bool
	var foundExclude bool

	for _, result := range results {
		if result.Code == excludeCode {
			foundExclude = true
		}
		if result.Code == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("result with code '%s' was found but should not have been", excludeCode))
	if includeCode != checks.Code("") {
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
