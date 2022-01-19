package testutil

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil/filesystem"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func ScanHCL(source string, t *testing.T, additionalOptions ...scanner.Option) rules.Results {
	modules := CreateModulesFromSource(source, ".tf", t)
	s := scanner.New()
	for _, opt := range additionalOptions {
		opt(s)
	}
	res, err := s.Scan(modules)
	require.NoError(t, err)
	for _, result := range res {
		if result.NarrowestRange() == nil {
			t.Errorf("result has no range specified: %#v", result)
		}
	}
	return res
}

func ScanJSON(source string, t *testing.T) rules.Results {
	modules := CreateModulesFromSource(source, ".tf.json", t)
	res, _ := scanner.New().Scan(modules)
	return res
}

func CreateModulesFromSource(source string, ext string, t *testing.T) []block.Module {
	fs, err := filesystem.New()
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.WriteTextFile("test"+ext, source); err != nil {
		t.Fatal(err)
	}
	path := fs.RealPath("test" + ext)
	modules, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func AssertCheckCode(t *testing.T, includeCode string, excludeCode string, results []rules.Result, messages ...string) {
	var foundInclude bool
	var foundExclude bool

	var excludeText string

	if !validateCodes(includeCode, excludeCode) {
		t.Logf("Either includeCode (%s) or excludeCode (%s) was invalid ", includeCode, excludeCode)
		t.FailNow()
	}

	var found []string
	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			continue
		}
		found = append(found, res.Rule().ShortCode)
		if res.Rule().LongID() == excludeCode {
			foundExclude = true
			excludeText = res.Description()
		}
		if res.Rule().LongID() == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been: %s", excludeCode, excludeText))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been - found [%s]", includeCode, strings.Join(found, ", ")))
	}

	if t.Failed() {
		t.Log(strings.ReplaceAll(t.Name(), "_", " "))
	}
}

func validateCodes(includeCode, excludeCode string) bool {
	if includeCode != "" {
		if _, err := scanner.GetRuleById(includeCode); err != nil {
			return false
		}
	}

	if excludeCode != "" {
		if _, err := scanner.GetRuleById(excludeCode); err != nil {
			return false
		}
	}
	return true
}
