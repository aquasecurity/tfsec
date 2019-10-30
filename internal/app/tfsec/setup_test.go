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

func assertCheckCodeExists(t *testing.T, code checks.Code, results []checks.Result) {
	if code == checks.None {
		return
	}
	var found bool
	for _, result := range results {
		if result.Code == code {
			found = true
			break
		}
	}
	assert.True(t, found, fmt.Sprintf("result with code '%s' was not found", code))
}
