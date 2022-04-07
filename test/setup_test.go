package test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runWithArgs(args ...string) (stdout string, stderr string, exit int) {
	sOut := bytes.NewBuffer([]byte{})
	sErr := bytes.NewBuffer([]byte{})
	rootCmd := cmd.Root()
	rootCmd.SetOut(sOut)
	rootCmd.SetErr(sErr)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	if err != nil {
		if err.Error() != "" {
			_, _ = fmt.Fprintf(sErr, "Error: %s\n", err)
		}
		exit = 1
		var exitErr *cmd.ExitCodeError
		if errors.As(err, &exitErr) {
			exit = exitErr.Code()
		}
	}
	return sOut.String(), sErr.String(), exit
}

func parseJSON(t *testing.T, data string) []scan.FlatResult {
	jsonResults := struct {
		Results []scan.FlatResult `json:"results"`
	}{}
	require.NoError(t, json.Unmarshal([]byte(data), &jsonResults))
	return jsonResults.Results
}

func parseLovely(t *testing.T, data string) []scan.FlatResult {
	var results []scan.FlatResult
	idMarker := "        ID"
	regoMarker := "Rego Package"
	var hasExampleCodeError bool
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, "Failed to render code") {
			hasExampleCodeError = true
		}
		if strings.Contains(line, idMarker) {
			longID := strings.TrimSpace(strings.Split(line, idMarker)[1])
			parts := strings.Split(longID, " ")
			longID = parts[len(parts)-1]
			results = append(results, scan.FlatResult{
				LongID: longID,
			})
			assert.False(t, hasExampleCodeError, "result %s should have highlighted code output", longID)
			hasExampleCodeError = false
		} else if strings.Contains(line, regoMarker) {
			longID := strings.TrimSpace(strings.Split(line, regoMarker)[1])
			parts := strings.Split(longID, " ")
			longID = parts[len(parts)-1]
			results = append(results, scan.FlatResult{
				LongID: longID,
			})
			hasExampleCodeError = false
		}

	}
	return results
}

func parseCSV(t *testing.T, data string) []scan.FlatResult {
	var results []scan.FlatResult
	records, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	require.NoError(t, err)
	idColumn := "rule_id"
	var idIndex int
	for i, record := range records {
		if i == 0 {
			var found bool
			for j, col := range record {
				if col == idColumn {
					idIndex = j
					found = true
					break
				}
			}
			require.True(t, found, "Column %s should exist in CSV header", idColumn)
			continue
		}
		results = append(results, scan.FlatResult{
			LongID: record[idIndex],
		})
	}
	return results
}

type checkstyleOutput struct {
	XMLName xml.Name `xml:"checkstyle"`
	Version string   `xml:"version,attr"`
	Files   []struct {
		Errors []struct {
			Source string `xml:"source,attr"`
		} `xml:"error"`
	} `xml:"file"`
}

func parseCheckStyle(t *testing.T, data string) []scan.FlatResult {
	var output checkstyleOutput
	require.NoError(t, xml.Unmarshal([]byte(data), &output))
	var results []scan.FlatResult
	assert.Equal(t, "checkstyle", output.XMLName.Local)
	assert.NotEmpty(t, output.Version)
	for _, file := range output.Files {
		for _, e := range file.Errors {
			results = append(results, scan.FlatResult{
				LongID: e.Source,
			})
		}
	}
	return results
}

type jUnitTestSuite struct {
	XMLName   xml.Name `xml:"testsuite"`
	TestCases []struct {
		XMLName xml.Name `xml:"testcase"`
		Name    string   `xml:"name,attr"`
	} `xml:"testcase"`
}

func parseJUnit(t *testing.T, data string) []scan.FlatResult {
	var output jUnitTestSuite
	require.NoError(t, xml.Unmarshal([]byte(data), &output))
	var results []scan.FlatResult
	for _, testCase := range output.TestCases {
		longID := strings.TrimPrefix(strings.Split(testCase.Name, "]")[0], "[")
		results = append(results, scan.FlatResult{
			LongID: longID,
		})
	}
	return results
}

func parseSARIF(t *testing.T, data string) []scan.FlatResult {
	report, err := sarif.FromString(data)
	require.NoError(t, err)
	var results []scan.FlatResult
	for _, run := range report.Runs {
		for _, res := range run.Results {
			require.NotNil(t, res.RuleID)
			results = append(results, scan.FlatResult{
				LongID: *res.RuleID,
			})
		}
	}
	return results
}

func assertLovelyOutputMatchesJSON(t *testing.T, lovely string, j string) {
	jsonResults := parseJSON(t, j)
	lovelyResults := parseLovely(t, lovely)
	assertResultSetsEqual(t, jsonResults, lovelyResults)
}

func assertResultsContain(t *testing.T, results []scan.FlatResult, longID string) {
	var found bool
	for _, result := range results {
		if result.LongID == longID {
			found = true
			break
		}
	}
	assert.True(t, found, "results should have contained '%s'", longID)
}

func assertResultsNotContain(t *testing.T, results []scan.FlatResult, longID string) {
	var found bool
	for _, result := range results {
		if result.LongID == longID {
			found = true
			break
		}
	}
	assert.False(t, found, "results should not have contained '%s'", longID)
}

func assertResultSetsEqual(t *testing.T, expectedResults []scan.FlatResult, actualResults []scan.FlatResult) {
	for _, expected := range expectedResults {
		var found bool
		for _, actual := range actualResults {
			if actual.LongID == expected.LongID {
				found = true
				break
			}
		}
		assert.True(t, found, "'%s' should have been output", expected.LongID)
	}
	for _, actual := range actualResults {
		var found bool
		for _, expected := range expectedResults {
			if actual.LongID == expected.LongID {
				found = true
				break
			}
		}
		assert.True(t, found, "'%s' should not have been output", actual.LongID)
	}
}

func assertCSVOutputMatchesJSON(t *testing.T, out string, j string) {
	jsonResults := parseJSON(t, j)
	results := parseCSV(t, out)
	assertResultSetsEqual(t, jsonResults, results)
}

func assertCheckStyleOutputMatchesJSON(t *testing.T, out string, j string) {
	jsonResults := parseJSON(t, j)
	results := parseCheckStyle(t, out)
	assertResultSetsEqual(t, jsonResults, results)
}

func assertJUnitOutputMatchesJSON(t *testing.T, out string, j string) {
	jsonResults := parseJSON(t, j)
	results := parseJUnit(t, out)
	assertResultSetsEqual(t, jsonResults, results)
}

func assertSARIFOutputMatchesJSON(t *testing.T, out string, j string) {
	jsonResults := parseJSON(t, j)
	results := parseSARIF(t, out)
	assertResultSetsEqual(t, jsonResults, results)
}
