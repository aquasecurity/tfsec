package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_GkeLegacyAuthEnabled(t *testing.T) {

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
			mustIncludeResultCode: rules.GkeLegacyAuthEnabled,
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
			mustExcludeResultCode: rules.GkeLegacyAuthEnabled,
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
			mustIncludeResultCode: rules.GkeLegacyAuthEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
