package monitor
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AzureCaptureAllActivities(t *testing.T) {
 	expectedCode := "azure-monitor-capture-all-activities"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "profile with no categories fails check",
 			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "profile with missing Action category fails check",
 			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = [
 	  "Delete",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "profile with missing Delete category fails check",
 			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = [
 	  "Action",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "profile with missing Write category fails check",
 			source: `
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = [
 	  "Action",
 	  "Delete",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "profile with required categories passes check",
 			source: `
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   categories = [
 	  "Action",
 	  "Delete",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 365
   }
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
