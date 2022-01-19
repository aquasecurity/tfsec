package gke

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GkeNodeMetadataExposed(t *testing.T) {
	expectedCode := "google-gke-node-metadata-security"

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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to EXPOSE",
			source: `
resource "google_container_cluster" "gke" {
}

 resource "google_container_node_pool" "gke" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "EXPOSE"
 		}
 	}
	cluster = google_container_cluster.gke.id

 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to UNSPECIFIED",
			source: `
 resource "google_container_cluster" "gke" {
 }

 resource "google_container_node_pool" "gke" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "UNSPECIFIED"
 		}
 	}
	cluster = google_container_cluster.gke.id
 }`,
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to SECURE",
			source: `
 resource "google_container_cluster" "gke" {
 }
  
 resource "google_container_node_pool" "gke" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "SECURE"
 		}
 	}
	cluster = google_container_cluster.gke.id
 }`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check google_container_node_pool with node_config.workload_metadata_config.node_metadata set to GKE_METADATA_SERVER",
			source: `
 resource "google_container_cluster" "gke" {
 }
		   
 resource "google_container_node_pool" "gke" {
 	node_config {
 		workload_metadata_config {
 			node_metadata = "GKE_METADATA_SERVER"
 		}
 	}
	cluster = google_container_cluster.gke.id
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
