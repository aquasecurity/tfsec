package gke
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_GkeEnforcePSPTest(t *testing.T) {
// 	expectedCode := "google-gke-enforce-pod-security-policy"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check google_container_cluster with pod_security_policy_config.enabled set to false",
// 			source: `
// resource "google_container_cluster" "gke" {
// 	pod_security_policy_config {
//     enabled = "false"
//   }
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check google_container_cluster with pod_security_policy_config block not set",
// 			source: `
// resource "google_container_cluster" "gke" {
// 
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check google_container_cluster with pod_security_policy_config.enabled set to true",
// 			source: `
// resource "google_container_cluster" "gke" {
// 	pod_security_policy_config {
//     enabled = "true"
//   }
// }`,
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
// 
// }
