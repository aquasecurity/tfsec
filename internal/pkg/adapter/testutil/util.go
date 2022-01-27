package testutil

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/types"
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

	if expectedJson[0] == '[' {
		var expectedSlice []map[string]interface{}
		require.NoError(t, json.Unmarshal(expectedJson, &expectedSlice))
		var actualSlice []map[string]interface{}
		require.NoError(t, json.Unmarshal(actualJson, &actualSlice))
		assert.Equal(t, expectedSlice, actualSlice, "defsec adapted and expected values do not match")
	} else {
		var expectedMap map[string]interface{}
		require.NoError(t, json.Unmarshal(expectedJson, &expectedMap))
		var actualMap map[string]interface{}
		require.NoError(t, json.Unmarshal(actualJson, &actualMap))
		assert.Equal(t, expectedMap, actualMap, "defsec adapted and expected values do not match")
	}
}

func Int(i int) types.IntValue {
	return types.Int(i, types.NewTestMetadata())
}

func Bool(b bool) types.BoolValue {
	return types.Bool(b, types.NewTestMetadata())
}

func String(s string) types.StringValue {
	return types.String(s, types.NewTestMetadata())
}

func StringSlice(s []string) []types.StringValue {
	var slice []types.StringValue
	for _, str := range s {
		slice = append(slice, types.String(str, types.NewTestMetadata()))
	}
	return slice
}

func Map(m map[string]string) types.MapValue {
	meta := types.NewTestMetadata()
	return types.Map(m, &meta)
}
