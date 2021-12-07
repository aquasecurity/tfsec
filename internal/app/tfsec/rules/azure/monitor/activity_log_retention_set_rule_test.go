package monitor
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AzureActivityLogRetentionSet(t *testing.T) {
// 	expectedCode := "azure-monitor-activity-log-retention-set"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "TODO: add test name",
// 			source: `
// resource "azurerm_monitor_log_profile" "bad_example" {
//   name = "bad_example"
// 
//   retention_policy {
//     enabled = true
//     days    = 7
//   }
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "TODO: add test name",
// 			source: `
// resource "azurerm_monitor_log_profile" "good_example" {
//   name = "good_example"
// 
//   retention_policy {
//     enabled = true
//     days    = 365
//   }
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// }
