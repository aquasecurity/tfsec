package main

import (
	"github.com/stretchr/testify/assert"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"testing"
)

func Test_IfIgnoreWarningsSetShouldRemoveWarningScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 1
	twoScanResultsWithOneWarning := []scanner.Result {
		{
			Severity: scanner.SeverityError,
		},
		{
			Severity: scanner.SeverityWarning,
		},
	}

	actualResults := RemoveDuplicatesAndUnwanted(twoScanResultsWithOneWarning, true, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}

func Test_IfIgnoreWarningsIsNotSetThenWarningShouldBeInScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 2
	twoScanResultsWithOneWarning := []scanner.Result {
		{
			Severity: scanner.SeverityError,
		},
		{
			Severity: scanner.SeverityWarning,
		},
	}

	actualResults := RemoveDuplicatesAndUnwanted(twoScanResultsWithOneWarning, false, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}
