package parser

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/hashicorp/hcl/v2"
)

func LoadDirectory(fullPath string) ([]*hcl.File, error) {

	hclParser := hclparse.NewParser()

	fileInfos, err := ioutil.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	for _, info := range fileInfos {
		if info.IsDir() {
			continue
		}

		if filepath.Ext(info.Name()) != ".tf" {
			continue
		}

		path := filepath.Join(fullPath, info.Name())
		_, diag := hclParser.ParseHCLFile(path)
		if diag != nil && diag.HasErrors() {
			return nil, diag
		}
	}

	var files []*hcl.File
	for _, file := range hclParser.Files() {
		files = append(files, file)
	}

	return files, nil
}

func LoadTFVars(filename string) (map[string]cty.Value, error) {

	inputVars := make(map[string]cty.Value)

	if filename == "" {
		return inputVars, nil
	}

	src, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	variableFile, _ := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	attrs, _ := variableFile.Body.JustAttributes()

	for _, attr := range attrs {
		debug.Log("Setting '%s' from tfvars file at %s", attr.Name, filename)
		inputVars[attr.Name], _ = attr.Expr.Value(&hcl.EvalContext{})
	}

	return inputVars, nil
}

func LoadBlocksFromFile(file *hcl.File) (hcl.Blocks, error) {

	contents, diagnostics := file.Body.Content(terraformSchema)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, diagnostics
	}

	if contents == nil {
		return nil, fmt.Errorf("file contents is empty")
	}

	return contents.Blocks, nil
}


type ModulesMetadata struct {
	Modules []ModuleMetadata `json:"Modules"`
}

type ModuleMetadata struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

func LoadModuleMetadata(fullPath string) (*ModulesMetadata, error) {
	metadataPath := filepath.Join(fullPath, ".terraform/modules/modules.json")
	if _, err := os.Stat(metadataPath); err != nil {
		return nil, err
	}

	f, err := os.Open(metadataPath)
	if err != nil {
		return nil, err
	}
	defer func(){ _ = f.Close() }()

	var metadata ModulesMetadata
	if err := json.NewDecoder(f).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}
