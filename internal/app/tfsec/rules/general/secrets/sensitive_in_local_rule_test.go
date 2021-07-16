package secrets

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSSensitiveLocals(t *testing.T) {
	expectedCode := "general-secrets-sensitive-in-local"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check non-sensitive local",
			source: `
locals {
	something = "something"
}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
