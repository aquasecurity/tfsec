package gke

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GkeLegacyAuthEnabled(t *testing.T) {
	expectedCode := "google-gke-no-legacy-authentication"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_container_cluster with master_auth static user/pass not disable",
			source: `
 resource "google_container_cluster" "gke" {
 
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_cluster with master_auth static user/pass disabled",
			source: `
 resource "google_container_cluster" "gke" {
 	master_auth {
     username = ""
     password = ""
 	}
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check google_container_cluster with client cert enabled and master_auth static user/pass disabled",
			source: `
 resource "google_container_cluster" "gke" {
 	master_auth {
         username = ""
         password = ""
 		client_certificate_config {
             issue_client_certificate = true
         }
 	}
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
