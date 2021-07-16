package gke

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GkeShieldedNodesDisabled(t *testing.T) {
	expectedCode := "google-gke-node-shielding-enabled"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_container_cluster with enable_shielded_nodes set to false",
			source: `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "false"

}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes not set",
			source: `
resource "google_container_cluster" "gke" {
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes set to true",
			source: `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "true"

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
