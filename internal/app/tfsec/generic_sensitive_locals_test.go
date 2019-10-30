package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSSensitiveLocals(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check sensitive local with value",
			source: `
locals {
	password = "secret"
}`,
			expectedResultCode: checks.GenericSensitiveLocals,
		},
		{
			name: "check non-sensitive local",
			source: `
locals {
	something = "something"
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
