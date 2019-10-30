package parser

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_BasicParsing(t *testing.T) {
	parser := New()

	path := createTestFile("test.tf", `

locals {
	proxy = var.cats_mother
}

variable "cats_mother" {
	default = "boots"
}

provider "cats" {

}

resource "cats_cat" "mittens" {
	name = "mittens"
	special = true
}

resource "cats_kitten" "the-great-destroyer" {
	name = "the great destroyer"
    parent = cats_cat.mittens.name
}

data "cats_cat" "the-cats-mother" {
	name = local.proxy
}


`)

	blocks, ctx, err := parser.ParseDirectory(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}

	// variable
	variables := blocks.OfType("variable")
	require.Len(t, variables, 1)
	assert.Equal(t, "variable", variables[0].Type)
	require.Len(t, variables[0].Labels, 1)
	assert.Equal(t, "cats_mother", variables[0].Labels[0])
	attributes, diagnostics := variables[0].Body.JustAttributes()
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	require.Len(t, attributes, 1)
	assert.Equal(t, "default", attributes["default"].Name)
	val, diagnostics := attributes["default"].Expr.Value(nil)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	assert.Equal(t, "boots", val.AsString())

	// provider
	providerBlocks := blocks.OfType("provider")
	require.Len(t, providerBlocks, 1)
	assert.Equal(t, "provider", providerBlocks[0].Type)
	require.Len(t, providerBlocks[0].Labels, 1)
	assert.Equal(t, "cats", providerBlocks[0].Labels[0])

	// resources
	resourceBlocks := blocks.OfType("resource")
	require.Len(t, resourceBlocks, 2)
	require.Len(t, resourceBlocks[0].Labels, 2)

	assert.Equal(t, "resource", resourceBlocks[0].Type)
	assert.Equal(t, "cats_cat", resourceBlocks[0].Labels[0])
	assert.Equal(t, "mittens", resourceBlocks[0].Labels[1])
	attributes, diagnostics = resourceBlocks[0].Body.JustAttributes()
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	require.Len(t, attributes, 2)
	assert.Equal(t, "name", attributes["name"].Name)
	val, diagnostics = attributes["name"].Expr.Value(nil)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	assert.Equal(t, "mittens", val.AsString())
	val, diagnostics = attributes["special"].Expr.Value(nil)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	assert.True(t, val.True())

	assert.Equal(t, "resource", resourceBlocks[1].Type)
	assert.Equal(t, "cats_kitten", resourceBlocks[1].Labels[0])
	assert.Equal(t, "the-great-destroyer", resourceBlocks[1].Labels[1])
	attributes, diagnostics = resourceBlocks[1].Body.JustAttributes()
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	require.Len(t, attributes, 2)
	assert.Equal(t, "name", attributes["name"].Name)
	val, diagnostics = attributes["name"].Expr.Value(nil)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	assert.Equal(t, "the great destroyer", val.AsString())
	val, diagnostics = attributes["parent"].Expr.Value(ctx)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors(), diagnostics.Error())
	}
	assert.Equal(t, "mittens", val.AsString())

	// data
	dataBlocks := blocks.OfType("data")
	require.Len(t, dataBlocks, 1)
	require.Len(t, dataBlocks[0].Labels, 2)

	assert.Equal(t, "data", dataBlocks[0].Type)
	assert.Equal(t, "cats_cat", dataBlocks[0].Labels[0])
	assert.Equal(t, "the-cats-mother", dataBlocks[0].Labels[1])
	attributes, diagnostics = dataBlocks[0].Body.JustAttributes()
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors())
	}
	require.Len(t, attributes, 1)
	assert.Equal(t, "name", attributes["name"].Name)
	val, diagnostics = attributes["name"].Expr.Value(ctx)
	if diagnostics != nil {
		require.False(t, diagnostics.HasErrors(), diagnostics.Error())
	}
	assert.Equal(t, "boots", val.AsString())
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
