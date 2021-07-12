package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_GkeNodeMetadataExposed(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
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
			mustIncludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustIncludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustIncludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustIncludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustExcludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustExcludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustExcludeResultCode: rules.GkeNodeMetadataExposed,
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
			mustExcludeResultCode: rules.GkeNodeMetadataExposed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
