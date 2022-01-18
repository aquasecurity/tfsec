package gke

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GCPGKENodeServiceAccount(t *testing.T) {
	expectedCode := "google-gke-use-service-account"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "does not define service account in container cluster and uses default node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 	remove_default_node_pool = false
 	node_config {
 	}
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "does not define service account in container cluster but removes default node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 	remove_default_node_pool = true
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "does not define node_config in container cluster and uses default node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "defines service account in container cluster",
			source: `
 resource "google_container_cluster" "my-cluster" {
 	node_config {
 		service_account = "anything"
 	}
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "does not define service account in container node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 }

 resource "google_container_node_pool" "my-np-cluster" {
 	node_config {
 	}
	 cluster = google_container_cluster.my-cluster.id
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "does not define node_config in container node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 }

 resource "google_container_node_pool" "my-np-cluster" {
	cluster = google_container_cluster.my-cluster.id
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "defines service account in container node pool",
			source: `
 resource "google_container_cluster" "my-cluster" {
 }

 resource "google_container_node_pool" "my-np-cluster" {
 	node_config {
 		service_account = "anything"
 	}
	cluster = google_container_cluster.my-cluster.id
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "defines service account in container node pool using reference",
			source: `
 resource "google_container_cluster" "my-cluster" {
 }

 resource "google_container_node_pool" "my-np-cluster" {
 	node_config {
 		service_account = google_service_account.service_account.email
 	}
	cluster = google_container_cluster.my-cluster.id
 }
 `,
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
