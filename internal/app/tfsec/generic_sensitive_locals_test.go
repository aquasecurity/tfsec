package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/general"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSSensitiveLocals(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check sensitive local with value",
			source: `
locals {
	password = "secret"
}`,
			mustIncludeResultCode: general.GenericSensitiveLocals,
		},
		{
			name: "check non-sensitive local",
			source: `
locals {
	something = "something"
}`,
			mustExcludeResultCode: general.GenericSensitiveLocals,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
