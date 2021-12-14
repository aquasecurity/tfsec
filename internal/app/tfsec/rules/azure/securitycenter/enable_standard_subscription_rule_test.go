package securitycenter
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AzureEnableStandardSubscription(t *testing.T) {
 	expectedCode := "azure-security-center-enable-standard-subscription"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "Tier set to free fails the check",
 			source: `
 resource "azurerm_security_center_subscription_pricing" "bad_example" {
   tier          = "Free"
   resource_type = "VirtualMachines"
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "Tier set to Standard passses the check",
 			source: `
 resource "azurerm_security_center_subscription_pricing" "good_example" {
   tier          = "Standard"
   resource_type = "VirtualMachines"
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
