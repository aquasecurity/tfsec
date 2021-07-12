package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSSensitiveLocals(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check sensitive local with value",
			source: `
locals {
	password = "secret"
}`,
			mustIncludeResultCode: rules.GenericSensitiveLocals,
		},
		{
			name: "check non-sensitive local",
			source: `
locals {
	something = "something"
}`,
			mustExcludeResultCode: rules.GenericSensitiveLocals,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
