package testutil

import (
	"path/filepath"
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
	scanner.OptionStopOnErrors()(s)
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

func CreateModulesFromSource(source string, ext string, t *testing.T) block.Modules {
	fs, err := filesystem.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fs.Close() }()
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

func AssertRuleFound(t *testing.T, ruleID string, results []rules.Result, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results)
	assert.True(t, found, append([]interface{}{message}, args...)...)
}

func AssertRuleNotFound(t *testing.T, ruleID string, results []rules.Result, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results)
	assert.False(t, found, append([]interface{}{message}, args...)...)
}

func ruleIDInResults(ruleID string, results []rules.Result) bool {
	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			continue
		}
		if res.Rule().LongID() == ruleID {
			return true
		}
	}
	return false
}
