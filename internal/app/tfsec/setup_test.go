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
