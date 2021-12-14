package gke
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_GkeAbacEnabled(t *testing.T) {
 	expectedCode := "google-gke-use-rbac-permissions"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check google_container_cluster with enable_legacy_abac set to true",
 			source: `
 resource "google_container_cluster" "gke" {
 	enable_legacy_abac = "true"
 	
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 	}
 
 	for _, test := range tests {
 		t.Run(test.name, func(t *testing.T) {
 
 			results := testutil.ScanHCL(test.source, t)
 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
 		})
 	}
 
 }
