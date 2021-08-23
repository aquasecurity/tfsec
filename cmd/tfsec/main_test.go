package main

import (
	"testing"

	"github.com/aquasecurity/defsec/result"

	"github.com/aquasecurity/defsec/severity"

	"github.com/stretchr/testify/assert"
)

func Test_IfIgnoreWarningsSetShouldRemoveWarningScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 1
	twoScanResultsWithOneWarning := []result.Result{
		{
			RuleID:   "1",
			Severity: severity.High,
		},
		{
			RuleID:   "2",
			Severity: severity.Medium,
		},
	}

	actualResults := removeDuplicatesAndUnwanted(twoScanResultsWithOneWarning, true, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}

func Test_IfIgnoreWarningsIsNotSetThenWarningShouldBeInScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 2
	twoScanResultsWithOneWarning := []result.Result{
		{
			RuleID:   "1",
			Severity: severity.High,
		},
		{
			RuleID:   "2",
			Severity: severity.Medium,
		},
	}

	actualResults := removeDuplicatesAndUnwanted(twoScanResultsWithOneWarning, false, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}
