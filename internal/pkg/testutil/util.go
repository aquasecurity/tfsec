package testutil

import (
    "path/filepath"
    "testing"

    "github.com/aquasecurity/defsec/rules"
    "github.com/aquasecurity/tfsec/internal/pkg/scanner"
    "github.com/aquasecurity/tfsec/internal/pkg/testutil/filesystem"
    "github.com/aquasecurity/trivy-config-parsers/terraform"
    "github.com/aquasecurity/trivy-config-parsers/terraform/parser"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
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
        if result.Range() == nil {
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

func CreateModulesFromSource(source string, ext string, t *testing.T) terraform.Modules {
    fs, err := filesystem.New()
    if err != nil {
        t.Fatal(err)
    }
    defer func() { _ = fs.Close() }()
    if err := fs.WriteTextFile("test"+ext, source); err != nil {
        t.Fatal(err)
    }
    path := fs.RealPath("test" + ext)
    p := parser.New(parser.OptionStopOnHCLError())
    if err := p.ParseDirectory(filepath.Dir(path)); err != nil {
        t.Fatal(err)
    }
    modules, _, err := p.EvaluateAll()
    if err != nil {
        t.Fatalf("parse error: %s", err)
    }
    return modules
}

func AssertRuleFound(t *testing.T, ruleID string, results []rules.Result, message string, args ...interface{}) {
    found := ruleIDInResults(ruleID, results)
    assert.True(t, found, append([]interface{}{message}, args...)...)
    for _, result := range results {
        if result.Rule().LongID() == ruleID {
            m := result.Metadata()
            meta := &m
            for meta != nil {
                assert.NotNil(t, meta.Range(), 0)
                assert.Greater(t, meta.Range().GetStartLine(), 0)
                assert.Greater(t, meta.Range().GetEndLine(), 0)
                meta = meta.Parent()
            }
        }
    }
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
