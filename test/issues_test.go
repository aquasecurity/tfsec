package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// see https://github.com/aquasecurity/tfsec/issues/1661
func Test_Issue_1661(t *testing.T) {
	out, err, _ := runWithArgs("./testdata/issues/1661")
	results := parseLovely(t, out)
	assert.Equal(t, "", err)
	assertResultsNotContain(t, results, "aws-rds-enable-performance-insights-encryption")
}
