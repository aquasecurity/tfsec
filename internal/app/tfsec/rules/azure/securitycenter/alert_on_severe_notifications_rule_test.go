package securitycenter

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AzureAlertOnSevereNotifications(t *testing.T) {
	expectedCode := "azure-security-center-alert-on-severe-notifications"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "contact with alerts turned off fails check",
			source: `
resource "azurerm_security_center_contact" "bad_example" {
  email = "bad_example@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = false
  alerts_to_admins    = false
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "contact with alerts turned on passes check",
			source: `
resource "azurerm_security_center_contact" "good_example" {
  email = "good_example@example.com"
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
