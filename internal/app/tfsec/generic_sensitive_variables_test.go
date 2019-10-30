package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSSensitiveVariables(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check sensitive variable with value",
			source: `
variable "db_password" {
	default = "something"
}`,
			expectedResultCode: checks.GenericSensitiveVariables,
		},
		{
			name: "check sensitive variable without value",
			source: `
variable "db_password" {
	default = ""
}`,
			expectedResultCode: checks.None,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
