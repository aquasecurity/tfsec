package testutils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
)

func CreateModulesFromSource(source string, ext string, t *testing.T) []block.Module {
	path := CreateTestFile("test"+ext, source)
	modules, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func CreateTestFile(filename, contents string) string {
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
