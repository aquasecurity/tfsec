package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSSensitiveVariables(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check sensitive variable with value",
			source: `
variable "db_password" {
	default = "something"
}`,
			expectsResults: true,
		},
		{
			name: "check sensitive variable without value",
			source: `
variable "db_password" {
	default = ""
}`,
			expectsResults: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assert.Equal(t, test.expectsResults, len(results) > 0)
		})
	}

}
