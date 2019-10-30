package tfsec

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/checks"
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
)

func scanSource(source string) []checks.Result {
	blocks, ctx := createBlocksFromSource(source)
	return scanner.New().Scan(blocks, ctx)
}

func createBlocksFromSource(source string) (hcl.Blocks, *hcl.EvalContext) {
	path := createTestFile("test.tf", source)
	blocks, ctx, err := parser.New().ParseFile(path)
	if err != nil {
		panic(err)
	}
	return blocks, ctx
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
	if includeCode != checks.None {
		assert.True(t, foundInclude, fmt.Sprintf("result with code '%s' was not found but should have been", includeCode))
	}
}
