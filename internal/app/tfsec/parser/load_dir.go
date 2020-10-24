package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/hashicorp/hcl/v2"
)

var knownFiles = make(map[string]struct{})

func CountFiles() int {
	return len(knownFiles)
}

func LoadDirectory(fullPath string) ([]*hcl.File, error) {

	t := timer.Start(timer.DiskIO)
	defer t.Stop()

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
			_,_ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", diag)
			continue
		}

		knownFiles[path] = struct{}{}
	}

	var files []*hcl.File
	for _, file := range hclParser.Files() {
		files = append(files, file)
	}

	return files, nil
}
