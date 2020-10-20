package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/hashicorp/hcl/v2"
)

func LoadDirectory(fullPath string, excludedDirectories []string) ([]*hcl.File, error) {

	hclParser := hclparse.NewParser()

	if err := filepath.Walk(fullPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if filepath.Ext(info.Name()) != ".tf" {
				return nil
			}

			for _, excluded := range excludedDirectories {
				if !strings.HasSuffix(excluded, string(filepath.Separator)) {
					excluded = fmt.Sprintf("%s%s", excluded, string(filepath.Separator))
				}
				if strings.HasPrefix(path, excluded) {
					return nil
				}
			}

			_, diag := hclParser.ParseHCLFile(path)
			if diag != nil && diag.HasErrors() {
				return diag
			}

			return nil
		}); err != nil {
		return nil, err
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
