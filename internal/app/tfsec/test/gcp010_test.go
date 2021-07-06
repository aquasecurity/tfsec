package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_GkeShieldedNodesDisabled(t *testing.T) {

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
			mustIncludeResultCode: rules.GkeShieldedNodesDisabled,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes not set",
			source: `
resource "google_container_cluster" "gke" {
}`,
			mustIncludeResultCode: rules.GkeShieldedNodesDisabled,
		},
		{
			name: "check google_container_cluster with enable_shielded_nodes set to true",
			source: `
resource "google_container_cluster" "gke" {
	enable_shielded_nodes = "true"

}`,
			mustExcludeResultCode: rules.GkeShieldedNodesDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
