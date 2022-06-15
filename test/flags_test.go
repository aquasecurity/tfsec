package test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/version"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func Test_Flag_NonExistant(t *testing.T) {
	_, err, exit := runWithArgs("./testdata/pass", "--not-a-real-flag")
	assert.Contains(t, err, "unknown flag: --not-a-real-flag")
	assert.Equal(t, 1, exit)
}

func Test_Flag_SingleThread(t *testing.T) {
	// here we test that everything still works as normal with the flag
	// as it's difficult to test that multiple go-routines aren't used...
	out, err, exit := runWithArgs("--single-thread", "./testdata/pass")
	assert.Greater(t, len(out), 0)
	assert.Len(t, err, 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_DisableGrouping(t *testing.T) {
	out, _, exit := runWithArgs("--disable-grouping", "./testdata/group")
	assert.NotContains(t, out, "Individual Causes")
	assert.Equal(t, 1, exit)
}

func Test_Flag_IgnoreHCLErrors(t *testing.T) {
	_, err, exit := runWithArgs("./testdata/badhcl", "--ignore-hcl-errors")
	assert.Len(t, err, 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_NoColour(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/pass", "--no-colour")
	assert.NotContains(t, out, "\x1b[")
	assert.Equal(t, 0, exit)
}

func Test_Flag_NoColor(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/pass", "--no-color")
	assert.NotContains(t, out, "\x1b[")
	assert.Equal(t, 0, exit)
}

func Test_Flag_Version(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/pass", "--version")
	assert.Equal(t, "", err)
	assert.Equal(t, "You are running a locally built version of tfsec.\n", out)
	assert.Equal(t, 0, exit)
}

func Test_Flag_VersionWithOverride(t *testing.T) {
	backup := version.Version
	defer func() {
		version.Version = backup
	}()
	version.Version = "v1.2.3"
	out, err, exit := runWithArgs("./testdata/pass", "--version")
	assert.Equal(t, "", err)
	assert.Equal(t, "v1.2.3\n", out)
	assert.Equal(t, 0, exit)
}

func Test_Flag_Format_JSON_WithFailures(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/fail", "-f", "json")
	results := parseJSON(t, out)
	assert.Greater(t, len(results), 0)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Format_JSON_WithPass(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/pass", "-f", "json")
	results := parseJSON(t, out)
	assert.Equal(t, len(results), 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_Format_Lovely_With_Failures(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	out, _, exit := runWithArgs("./testdata/fail", "-f", "lovely")
	assertLovelyOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Format_Lovely_With_Pass(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/pass", "-f", "json")
	out, _, exit := runWithArgs("./testdata/pass", "-f", "lovely")
	assertLovelyOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 0, exit)
}

func Test_Flag_Format_CSV(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	out, _, exit := runWithArgs("./testdata/fail", "-f", "csv")
	assertCSVOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Format_Checkstyle(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	out, _, exit := runWithArgs("./testdata/fail", "-f", "checkstyle")
	assertCheckStyleOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Format_JUnit(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	out, _, exit := runWithArgs("./testdata/fail", "-f", "junit")
	assertJUnitOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Format_SARIF(t *testing.T) {
	jsonOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	out, _, exit := runWithArgs("./testdata/fail", "-f", "sarif")
	assertSARIFOutputMatchesJSON(t, out, jsonOut)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Exclude_Single(t *testing.T) {
	originalOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	originalResults := parseJSON(t, originalOut)
	require.Greater(t, len(originalResults), 0)

	exclude := originalResults[0].LongID
	out, _, _ := runWithArgs("./testdata/fail", "-f", "json", "-e", exclude)
	results := parseJSON(t, out)
	assertResultsNotContain(t, results, exclude)
	for _, original := range originalResults {
		if original.LongID != exclude {
			assertResultsContain(t, results, original.LongID)
		}
	}
}

func Test_Flag_Exclude_Multiple(t *testing.T) {
	originalOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	originalResults := parseJSON(t, originalOut)
	require.Greater(t, len(originalResults), 0)

	countExclude := 3
	var excludes []string
	for _, original := range originalResults {
		var already bool
		for _, exclude := range excludes {
			if exclude == original.LongID {
				already = true
				break
			}
		}
		if already {
			continue
		}
		excludes = append(excludes, original.LongID)
		if len(excludes) == countExclude {
			break
		}
	}
	if len(excludes) != countExclude {
		t.Fatal("not enough different issues in scenario to properly test --exclude")
	}

	out, _, _ := runWithArgs("./testdata/fail", "-f", "json", "-e", strings.Join(excludes, ","))
	results := parseJSON(t, out)
	for _, exclude := range excludes {
		assertResultsNotContain(t, results, exclude)
	}
	for _, original := range originalResults {
		var excluded bool
		for _, exclude := range excludes {
			if exclude == original.LongID {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		assertResultsContain(t, results, original.LongID)
	}
}

func Test_Flag_FilterResults(t *testing.T) {
	originalOut, _, _ := runWithArgs("./testdata/fail", "-f", "json")
	originalResults := parseJSON(t, originalOut)
	require.Greater(t, len(originalResults), 0)

	countFilter := 3
	var filters []string
	for _, original := range originalResults {
		var already bool
		for _, filter := range filters {
			if filter == original.LongID {
				already = true
				break
			}
		}
		if already {
			continue
		}
		filters = append(filters, original.LongID)
		if len(filters) == countFilter {
			break
		}
	}
	if len(filters) != countFilter {
		t.Fatal("not enough different issues in scenario to properly test --filter-results")
	}

	out, _, _ := runWithArgs("./testdata/fail", "-f", "json", "--filter-results", strings.Join(filters, ","))
	results := parseJSON(t, out)
	for _, filter := range filters {
		assertResultsContain(t, results, filter)
	}
	for _, original := range originalResults {
		var filtered bool
		for _, filter := range filters {
			if filter == original.LongID {
				filtered = true
				break
			}
		}
		if filtered {
			continue
		}
		assertResultsNotContain(t, results, original.LongID)
	}
}

func Test_Flag_SoftFail(t *testing.T) {
	for _, flag := range []string{"-s", "--soft-fail"} {
		t.Run(flag, func(t *testing.T) {
			out, _, exit := runWithArgs("./testdata/fail", flag)
			assert.Greater(t, len(parseLovely(t, out)), 0, "results should still be output when soft fail is used")
			assert.Equal(t, 0, exit)
		})
	}
}

func Test_Flag_TFVarsFile(t *testing.T) {
	_, _, exit := runWithArgs("./testdata/tfvars/tf")
	assert.Equal(t, 0, exit)
	out, _, exit := runWithArgs("./testdata/tfvars/tf", "--tfvars-file", "./testdata/tfvars/test.tfvars")
	assert.Greater(t, len(parseLovely(t, out)), 0, "results should be detected if the tfvars file has been applied")
	assert.Equal(t, 1, exit)
}

func Test_Flag_ExcludePath(t *testing.T) {

	tests := []struct {
		exclude string
		pass    bool
	}{
		{
			exclude: "something",
			pass:    false,
		},
		{
			exclude: "main.tf",
			pass:    true,
		},
		{
			exclude: "ain.tf",
			pass:    false,
		},
		{
			exclude: "./testdata/fail/main.tf",
			pass:    true,
		},
		{
			exclude: "fail/main.tf",
			pass:    true,
		},
		{
			exclude: "testdata",
			pass:    true,
		},
		{
			exclude: "",
			pass:    false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("--exclude-path %s", test.exclude), func(t *testing.T) {
			_, _, exit := runWithArgs("./testdata/fail", "--exclude-path", test.exclude)
			assert.Equal(t, test.pass, exit == 0)
		})
	}
}

func Test_Flag_Out(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "tfsec")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmp) }()
	file := filepath.Join(tmp, "tfsec_output.json")
	out, _, exit := runWithArgs("./testdata/fail", "--out", file, "-f", "json")
	assert.Len(t, out, 0)
	assert.Equal(t, 1, exit)
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	results := parseJSON(t, string(data))
	assert.Greater(t, len(results), 0)
}

func Test_Flag_CustomCheckDir(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/custom", "--custom-check-dir", "./testdata/custom")
	results := parseLovely(t, out)
	assert.Len(t, results, 1)
	assert.Equal(t, "", err)
	assert.Equal(t, 1, exit)
}

func Test_Flag_ConfigFile(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/config", "--config-file", "./testdata/config/config.yml")
	results := parseLovely(t, out)
	assertResultsNotContain(t, results, "aws-s3-enable-versioning")
	assert.Equal(t, "", err)
	assert.Equal(t, 1, exit)
}

func Test_Flag_Debug(t *testing.T) {
	// use json to ensure all debug goes to stderr and does not break json format
	for _, flag := range []string{"--debug", "--verbose"} {
		t.Run(flag, func(t *testing.T) {
			out, err, exit := runWithArgs("./testdata/pass", "-f", "json", flag)
			_ = parseJSON(t, out)
			assert.Contains(t, err, "terraform.parser")
			assert.Equal(t, 0, exit)
		})
	}
}

func Test_Flag_ConciseOutput(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/fail", "--concise-output")
	assert.Equal(t, "", err)
	_ = parseLovely(t, out)
	assert.NotContains(t, out, "adaptation")
	assert.Equal(t, 1, exit)
}

func Test_Flag_ExcludeDownloaded(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/external-module", "--exclude-downloaded-modules")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Len(t, results, 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_IncludePassed(t *testing.T) {
	before, err, _ := runWithArgs("./testdata/mixed")
	assert.Equal(t, "", err)
	beforeResults := parseLovely(t, before)
	out, err, _ := runWithArgs("./testdata/mixed", "--include-passed")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Greater(t, len(results), len(beforeResults), "passed results should be included")
}

func Test_Flag_IncludeIgnored(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/ignored", "--include-ignored")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Greater(t, len(results), 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_NoIgnores(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/ignored", "--no-ignores")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Greater(t, len(results), 0)
	assert.Equal(t, 1, exit)
}

func Test_Flag_ForceAllDirs(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/nested", "--force-all-dirs")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Greater(t, len(results), 0)
	assert.Equal(t, 1, exit)
}

func Test_Flag_RunStatistics(t *testing.T) {
	_, err, exit := runWithArgs("./testdata/pass", "--run-statistics")
	assert.Contains(t, err, "\n+--------")
	assert.Equal(t, 0, exit)
}

func Test_Flag_Workspace(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/nested", "--workspace", "testing")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Equal(t, len(results), 0)
	assert.Equal(t, 0, exit)
}

func Test_Flag_MinimumSeverity(t *testing.T) {
	before, err, _ := runWithArgs("./testdata/fail")
	assert.Equal(t, "", err)
	beforeResults := parseLovely(t, before)

	out, err, _ := runWithArgs("./testdata/fail", "--minimum-severity", "MEDIUM")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Less(t, len(results), len(beforeResults))
}

func Test_Flag_ConfigFile_WithMinimumSeverity(t *testing.T) {
	before, err, _ := runWithArgs("./testdata/fail")
	assert.Equal(t, "", err)
	beforeResults := parseLovely(t, before)

	out, err, _ := runWithArgs("./testdata/fail", "--config-file", "./testdata/config-minimum-severity/config.yml")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Less(t, len(results), len(beforeResults))
}

func Test_Flag_RegoPolicyDir(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/rego/tf", "--rego-policy-dir", "./testdata/rego/policies")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assertResultsContain(t, results, "custom.rego.rego.sauce")
	assert.Equal(t, 1, exit)
}

func Test_Flag_PrintRegoInput(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/fail", "--print-rego-input")
	assert.Equal(t, "", err)

	var raw interface{}

	require.NoError(t, json.Unmarshal([]byte(out), &raw))

	msi, ok := raw.(map[string]interface{})
	require.True(t, ok)

	_, ok = msi["aws"]
	require.True(t, ok)

	assert.Equal(t, 0, exit)
}

func Test_Flag_NoModuleDownloads(t *testing.T) {
	_ = os.RemoveAll("./.tfsec")
	out, err, exit := runWithArgs("./testdata/external-module", "--no-module-downloads", "--include-ignored")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assert.Len(t, results, 0, out)
	assert.Equal(t, 0, exit)
}

func Test_Flag_RegoOnly(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/rego/tf", "--rego-policy-dir", "./testdata/rego/policies", "--rego-only")
	assert.Equal(t, "", err)
	results := parseLovely(t, out)
	assertResultsContain(t, results, "custom.rego.rego.sauce")
	assert.Len(t, results, 1)
	assert.Equal(t, 1, exit)
}

func Test_Flag_ConfigFileUrl(t *testing.T) {
	configFileUrl := "https://raw.githubusercontent.com/aquasecurity/tfsec/master/_examples/with_config_overrides/.tfsec/config.yml"
	out, err, exit := runWithArgs("./testdata/with_config_overrides", "--config-file-url", configFileUrl)
	assert.Equal(t, "", err)
	result := parseLovely(t, out)
	assertResultsContain(t, result, "aws-s3-specify-public-access-block")
	assert.Len(t, result, 1)
	assert.Equal(t, 1, exit)
}

func Test_Flag_ConfigFileUrlNotFound(t *testing.T) {
	configFileUrl := "https://raw.githubusercontent.com/aquasecurity/tfsec/master/_examples/with_config_overrides/.tfsec/config_not_found.yml"
	out, err, exit := runWithArgs("./testdata/with_config_overrides", "--config-file-url", configFileUrl)
	assert.Equal(t, "", err)
	result := parseLovely(t, out)
	assertResultsContain(t, result, "aws-s3-specify-public-access-block")
	assert.Len(t, result, 9)
	assert.Equal(t, 1, exit)
}

func Test_Flag_CustomCheckUrlNotFound(t *testing.T) {
	customCheckUrl := "https://raw.githubusercontent.com/aquasecurity/tfsec/master/_examples/custom/.tfsec/custom_tfchecks_not_found.yaml"
	out, err, exit := runWithArgs("./testdata/custom_url", "--custom-check-url", customCheckUrl)
	assert.Equal(t, "", err)
	result := parseLovely(t, out)
	assertResultsContain(t, result, "aws-s3-specify-public-access-block")
	assert.Len(t, result, 43)
	assert.Equal(t, 1, exit)
}

func Test_Flag_CustomCheckUrl(t *testing.T) {
	customCheckUrl := "https://raw.githubusercontent.com/aquasecurity/tfsec/master/_examples/custom/.tfsec/custom_tfchecks.yaml"
	out, err, exit := runWithArgs("./testdata/custom_url", "--custom-check-url", customCheckUrl)
	assert.Equal(t, "", err)
	result := parseLovely(t, out)
	assertResultsContain(t, result, "aws-s3-specify-public-access-block")
	assert.Len(t, result, 55)
	assert.Equal(t, 1, exit)
}
