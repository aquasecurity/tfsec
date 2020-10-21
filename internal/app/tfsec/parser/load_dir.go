package parser

import (
	"io/ioutil"
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
