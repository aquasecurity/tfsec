package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSSensitiveAttributes(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check sensitive attribute",
			source: `
resource "evil_corp" "virtual_machine" {
	root_password = "secret"
}`,
			expectedResultCode: checks.GenericSensitiveAttributes,
		},
		{
			name: "check non-sensitive local",
			source: `
resource "evil_corp" "virtual_machine" {
	memory = 512
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
