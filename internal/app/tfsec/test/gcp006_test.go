package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GkeNodeMetadataExposed(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check google_container_cluster with node_config.workload_metadata_config.node_metadata set to EXPOSE",
			source: `
resource "google_container_cluster" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "EXPOSE"
		}
	}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_cluster with node_config.workload_metadata_config.node_metadata set to UNSPECIFIED",
			source: `
resource "google_container_cluster" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "UNSPECIFIED"
		}
	}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to EXPOSE",
			source: `
resource "google_container_node_pool" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "EXPOSE"
		}
	}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to UNSPECIFIED",
			source: `
resource "google_container_node_pool" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "UNSPECIFIED"
		}
	}
}`,
			mustIncludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_cluster with node_config.workload_metadata_config.node_metadata set to SECURE",
			source: `
resource "google_container_cluster" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "SECURE"
		}
	}
}`,
			mustExcludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_cluster with node_config.workload_metadata_config.node_metadata set to GKE_METADATA_SERVER",
			source: `
resource "google_container_cluster" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "GKE_METADATA_SERVER"
		}
	}
}`,
			mustExcludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to SECURE",
			source: `
resource "google_container_node_pool" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "SECURE"
		}
	}
}`,
			mustExcludeResultCode: checks.GkeNodeMetadataExposed,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to GKE_METADATA_SERVER",
			source: `
resource "google_container_node_pool" "gke" {
	node_config {
		workload_metadata_config {
			node_metadata = "GKE_METADATA_SERVER"
		}
	}
}`,
			mustExcludeResultCode: checks.GkeNodeMetadataExposed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
