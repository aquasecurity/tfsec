package testutils

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/aquasecurity/tfsec/internal/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func AssertDefsecEqual(t *testing.T, expected interface{}, actual interface{}) {
	expectedJson, err := json.MarshalIndent(expected, "", "\t")
	require.NoError(t, err)
	actualJson, err := json.MarshalIndent(actual, "", "\t")
	require.NoError(t, err)
	assert.Equal(t, expectedJson, actualJson, "defsec adapted and expected values do not match")
}
