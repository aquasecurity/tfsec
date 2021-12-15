package secrets

generator-locked
import (
"testing"
"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSSensitiveVariables(t *testing.T) {
	expectedCode := "general-secrets-sensitive-in-variable"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check sensitive variable with value",
			source: `
 variable "db_password" {
 	default = "something"
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check sensitive variable without default",
			source: `
 variable "db_password" {
 
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
