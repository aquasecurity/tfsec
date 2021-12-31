package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

var knownFiles = make(map[string]struct{})

type File struct {
	file *hcl.File
	path string
}

func CountFiles() int {
	return len(knownFiles)
}

func LoadDirectory(fullPath string, stopOnHCLError bool) ([]File, error) {

	t := metrics.Timer("timings", "disk i/o")
	t.Start()
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

		var parseFunc func(filename string) (*hcl.File, hcl.Diagnostics)

		switch true {
		case strings.HasSuffix(info.Name(), ".tf"):
			parseFunc = hclParser.ParseHCLFile
		case strings.HasSuffix(info.Name(), ".tf.json"):
			parseFunc = hclParser.ParseJSONFile
		default:
			continue
		}

		path := filepath.Join(fullPath, info.Name())
		_, diag := parseFunc(path)
		if diag != nil && diag.HasErrors() {
			if stopOnHCLError {
				return nil, diag
			}
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", diag)
			continue
		}

		knownFiles[path] = struct{}{}
	}

	var files []File
	for path, file := range hclParser.Files() {
		files = append(files, File{
			file: file,
			path: path,
		})
	}

	return files, nil
}
