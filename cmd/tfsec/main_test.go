package main

import (
	"testing"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/stretchr/testify/assert"
)

func Test_IfIgnoreWarningsSetShouldRemoveWarningScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 1
	twoScanResultsWithOneWarning := []result.Result{
		{
			RuleID:   "1",
			Severity: severity.Error,
		},
		{
			RuleID:   "2",
			Severity: severity.Warning,
		},
	}

	actualResults := RemoveDuplicatesAndUnwanted(twoScanResultsWithOneWarning, true, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}

func Test_IfIgnoreWarningsIsNotSetThenWarningShouldBeInScanResults(t *testing.T) {
	expectedResultsAfterFiltering := 2
	twoScanResultsWithOneWarning := []result.Result{
		{
			RuleID:   "1",
			Severity: severity.Error,
		},
		{
			RuleID:   "2",
			Severity: severity.Warning,
		},
	}

	actualResults := RemoveDuplicatesAndUnwanted(twoScanResultsWithOneWarning, false, false)
	assert.Len(t, actualResults, expectedResultsAfterFiltering)
}
