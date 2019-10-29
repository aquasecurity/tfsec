package tfsec

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/liamg/tfsec/internal/app/tfsec/models"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/hashicorp/hcl/v2"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

func Test_AWSClassicUsage(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name:           "check aws_db_security_group",
			source:         `resource "aws_db_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check aws_redshift_security_group",
			source:         `resource "aws_redshift_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check aws_elasticache_security_group",
			source:         `resource "aws_elasticache_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check for false positives",
			source:         `resource "my_resource" "my-resource" {}`,
			expectsResults: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assert.Equal(t, test.expectsResults, len(results) > 0)
		})
	}

}

func scanSource(source string) []models.Result {
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
