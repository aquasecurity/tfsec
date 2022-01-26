package testutils

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/aquasecurity/tfsec/internal/pkg/parser"
)

func CreateModulesFromSource(source string, ext string, t *testing.T) block.Modules {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "test"+ext)
	if err := ioutil.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)

	}
	defer func() {
		_ = os.Remove(path)
	}()
	modules, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		t.Errorf("parse error: %s", err)
	}
	return modules
}
