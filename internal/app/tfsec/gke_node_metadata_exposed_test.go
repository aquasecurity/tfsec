package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
)

func Test_GkeNodeMetadataExposed(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_container_cluster with workload_metadata_config.node_metadata set to EXPOSE",
			source: `
resource "google_container_cluster" "gke" {
	workload_metadata_config {
		node_metadata = "EXPOSE"
		}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_cluster with workload_metadata_config.node_metadata set to UNSPECIFIED",
			source: `
resource "google_container_cluster" "gke" {
	workload_metadata_config {
		node_metadata = "UNSPECIFIED"
		}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
