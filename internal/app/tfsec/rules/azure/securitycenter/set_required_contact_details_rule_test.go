package securitycenter

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureSetRequiredContactDetails(t *testing.T) {
	expectedCode := "azure-security-center-set-required-contact-details"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "contact with no phone specified fails check",
			source: `
resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_contact@example.com"

  alert_notifications = true
  alerts_to_admins    = true
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "contact with phone empty fails check",
			source: `
resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_contact@example.com"
  phone = ""

  alert_notifications = true
  alerts_to_admins    = true
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "contact with phone set passes check",
			source: `
resource "azurerm_security_center_contact" "good_example" {
  email = "good_contact@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
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
