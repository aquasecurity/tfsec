package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureNoSecretsInCustomData(t *testing.T) {
	expectedCode := "azure-compute-no-secrets-in-custom-data"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "virtual machine with a password in the custom_data fails check",
			source: `
			resource "azurerm_virtual_machine" "bad_example" {
				name = "bad_example"
				custom_data =<<EOF
DATABASE_PASSWORD=SomeSortOfPassword
EOF
			}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "virtual machine with a password in a string in the custom_data fails check",
			source: `
			resource "azurerm_virtual_machine" "bad_example" {
				name = "bad_example"
				custom_data =<<EOF
DATABASE_PASSWORD="SomeSortOfPassword"
EOF
			}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "virtual machine with no sensitive information in custom_data passes check",
			source: `
resource "azurerm_virtual_machine" "god_example" {
				name = "good_example"
				custom_data =<<EOF
GREETING_TEXT="Hello"
EOF
			}
`,
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
