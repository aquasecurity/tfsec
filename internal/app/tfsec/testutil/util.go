package testutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func ScanHCL(source string, t *testing.T, additionalOptions ...scanner.Option) []result.Result {
	modules := CreateModulesFromSource(source, ".tf", t)
	scanner := scanner.New(scanner.OptionStopOnErrors())
	for _, opt := range additionalOptions {
		opt(scanner)
	}
	return scanner.Scan(modules)
}

func ScanJSON(source string, t *testing.T) []result.Result {
	blocks := CreateModulesFromSource(source, ".tf.json", t)
	return scanner.New(scanner.OptionStopOnErrors()).Scan(blocks)
}

func CreateModulesFromSource(source string, ext string, t *testing.T) []block.Module {
	path := CreateTestFile("test"+ext, source)
	blocks, err := parser.New(filepath.Dir(path), parser.OptionStopOnHCLError()).ParseDirectory()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return blocks
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

func AssertCheckCode(t *testing.T, includeCode string, excludeCode string, results []result.Result, messages ...string) {
	var foundInclude bool
	var foundExclude bool

	var excludeText string

	if !validateCodes(includeCode, excludeCode) {
		t.Logf("Either includeCode (%s) or excludeCode (%s) was invalid ", includeCode, excludeCode)
		t.FailNow()
	}

	for _, res := range results {
		if res.RuleID == excludeCode {
			foundExclude = true
			excludeText = res.Description
		}
		if res.RuleID == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been: %s", excludeCode, excludeText))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been", includeCode))
	}

	if t.Failed() {
		t.Log(strings.ReplaceAll(t.Name(), "_", " "))
	}
}

func CreateTestFileWithModule(contents string, moduleContents string) string {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		panic(err)
	}

	rootPath := filepath.Join(dir, "main")
	modulePath := filepath.Join(dir, "module")

	if err := os.Mkdir(rootPath, 0755); err != nil {
		panic(err)
	}

	if err := os.Mkdir(modulePath, 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(rootPath, "main.tf"), []byte(contents), 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(modulePath, "main.tf"), []byte(moduleContents), 0755); err != nil {
		panic(err)
	}

	return rootPath
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
