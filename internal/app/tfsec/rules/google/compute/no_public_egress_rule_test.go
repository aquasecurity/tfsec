package compute
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_GoogleOpenOutboundFirewallRule(t *testing.T) {
 	expectedCode := "google-compute-no-public-egress"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check google_compute_firewall egress on 0.0.0.0/0",
 			source: `
 resource "google_compute_firewall" "my-firewall" {
 	destination_ranges = ["0.0.0.0/0"]
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check google_compute_firewall egress on /32",
 			source: `
 resource "google_compute_firewall" "my-firewall" {
 	destination_ranges = ["1.2.3.4/32"]
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
