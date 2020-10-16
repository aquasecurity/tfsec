package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GkeShieldedNodesDisabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_container_cluster with enable_shielded_nodes set to false",
			source: `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "false"

}`,
			mustIncludeResultCode: google.GkeShieldedNodesDisabled,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes not set",
			source: `
resource "google_container_cluster" "gke" {
}`,
			mustIncludeResultCode: google.GkeShieldedNodesDisabled,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes set to true",
			source: `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "true"

}`,
			mustExcludeResultCode: google.GkeShieldedNodesDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
