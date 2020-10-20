package parser

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zclconf/go-cty/cty"

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

	blocks, err := parser.ParseDirectory(filepath.Dir(path), nil, "")
	if err != nil {
		t.Fatal(err)
	}

	// variable
	variables := blocks.OfType("variable")
	require.Len(t, variables, 1)
	assert.Equal(t, "variable", variables[0].Type())
	require.Len(t, variables[0].Labels(), 1)
	assert.Equal(t, "cats_mother", variables[0].Labels()[0])
	defaultVal := variables[0].GetAttribute("default")
	require.NotNil(t, defaultVal)
	assert.Equal(t, cty.String, defaultVal.Value().Type())
	assert.Equal(t, "boots", defaultVal.Value().AsString())

	// provider
	providerBlocks := blocks.OfType("provider")
	require.Len(t, providerBlocks, 1)
	assert.Equal(t, "provider", providerBlocks[0].Type())
	require.Len(t, providerBlocks[0].Labels(), 1)
	assert.Equal(t, "cats", providerBlocks[0].Labels()[0])

	// resources
	resourceBlocks := blocks.OfType("resource")

	sort.Slice(resourceBlocks, func(i, j int) bool {
		return resourceBlocks[i].Labels()[0] < resourceBlocks[j].Labels()[0]
	})

	require.Len(t, resourceBlocks, 2)
	require.Len(t, resourceBlocks[0].Labels(), 2)

	assert.Equal(t, "resource", resourceBlocks[0].Type())
	assert.Equal(t, "cats_cat", resourceBlocks[0].Labels()[0])
	assert.Equal(t, "mittens", resourceBlocks[0].Labels()[1])

	assert.Equal(t, "mittens", resourceBlocks[0].GetAttribute("name").Value().AsString())
	assert.True(t, resourceBlocks[0].GetAttribute("special").Value().True())

	assert.Equal(t, "resource", resourceBlocks[1].Type())
	assert.Equal(t, "cats_kitten", resourceBlocks[1].Labels()[0])
	assert.Equal(t, "the great destroyer", resourceBlocks[1].GetAttribute("name").Value().AsString())
	assert.Equal(t, "mittens", resourceBlocks[1].GetAttribute("parent").Value().AsString())

	// data
	dataBlocks := blocks.OfType("data")
	require.Len(t, dataBlocks, 1)
	require.Len(t, dataBlocks[0].Labels(), 2)

	assert.Equal(t, "data", dataBlocks[0].Type())
	assert.Equal(t, "cats_cat", dataBlocks[0].Labels()[0])
	assert.Equal(t, "the-cats-mother", dataBlocks[0].Labels()[1])

	assert.Equal(t, "boots", dataBlocks[0].GetAttribute("name").Value().AsString())
}

func Test_Modules(t *testing.T) {

	path := createTestFileWithModule(`
module "my-mod" {
	source = "../module"
	input = "ok"
}

output "result" {
	value = module.my-mod.result
}
`,
		`
variable "input" {
	default = "?"
}

output "result" {
	value = var.input
}
`,
		"module",
	)

	parser := New()

	blocks, err := parser.ParseDirectory(path, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	modules := blocks.OfType("module")
	require.Len(t, modules, 1)
	module := modules[0]
	assert.Equal(t, "module", module.Type())
	assert.Equal(t, "module.my-mod", module.Name())
	inputAttr := module.GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	outputs := blocks.OfType("output")
	require.Len(t, outputs, 2)
	for _, output := range outputs {
		if output.inModule {
			assert.Equal(t, "module.my-mod.result", output.Name())
		} else {
			assert.Equal(t, "output.result", output.Name())
		}
		valAttr := output.GetAttribute("value")
		require.NotNil(t, valAttr)
		require.Equal(t, cty.String, valAttr.Type())
		assert.Equal(t, "ok", valAttr.Value().AsString())
	}

}

func Test_NestedParentModule(t *testing.T) {

	path := createTestFileWithModule(`
module "my-mod" {
	source = "../."
	input = "ok"
}

output "result" {
	value = module.my-mod.result
}
`,
		`
variable "input" {
	default = "?"
}

output "result" {
	value = var.input
}
`,
		"",
	)

	parser := New()

	blocks, err := parser.ParseDirectory(path, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	modules := blocks.OfType("module")
	require.Len(t, modules, 1)
	module := modules[0]
	assert.Equal(t, "module", module.Type())
	assert.Equal(t, "module.my-mod", module.Name())
	inputAttr := module.GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	outputs := blocks.OfType("output")
	require.Len(t, outputs, 2)
	for _, output := range outputs {
		if output.inModule {
			assert.Equal(t, "module.my-mod.result", output.Name())
		} else {
			assert.Equal(t, "output.result", output.Name())
		}
		valAttr := output.GetAttribute("value")
		require.NotNil(t, valAttr)
		require.Equal(t, cty.String, valAttr.Type())
		assert.Equal(t, "ok", valAttr.Value().AsString())
	}
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

func createTestFileWithModule(contents string, moduleContents string, moduleName string) string {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		panic(err)
	}

	rootPath := filepath.Join(dir, "main")
	modulePath := dir
	if len(moduleName) > 0 {
		modulePath = filepath.Join(modulePath, moduleName)
	}

	if err := os.Mkdir(rootPath, 0755); err != nil {
		panic(err)
	}

	if modulePath != dir {
		if err := os.Mkdir(modulePath, 0755); err != nil {
			panic(err)
		}
	}

	if err := ioutil.WriteFile(filepath.Join(rootPath, "main.tf"), []byte(contents), 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(modulePath, "main.tf"), []byte(moduleContents), 0755); err != nil {
		panic(err)
	}

	return rootPath
}
