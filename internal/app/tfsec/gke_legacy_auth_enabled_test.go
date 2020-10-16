package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GkeLegacyAuthEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_container_cluster with master_auth static user/pass not disable",
			source: `
resource "google_container_cluster" "gke" {

}`,
			mustIncludeResultCode: google.GkeLegacyAuthEnabled,
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
			mustExcludeResultCode: google.GkeLegacyAuthEnabled,
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
			mustIncludeResultCode: google.GkeLegacyAuthEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
