package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_GCPGKENodeServiceAccount(t *testing.T) {

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
			mustIncludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define service account in container cluster but removes default node pool",
			source: `
resource "google_container_cluster" "my-cluster" {
	remove_default_node_pool = true
}
`,
			mustExcludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define node_config in container cluster and uses default node pool",
			source: `
resource "google_container_cluster" "my-cluster" {
}
`,
			mustIncludeResultCode: rules.GCPGKENodeServiceAccount,
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
			mustExcludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define service account in container node pool",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
	node_config {
	}
}
`,
			mustIncludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define node_config in container node pool",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
}
`,
			mustIncludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "defines service account in container node pool",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
	node_config {
		service_account = "anything"
	}
}
`,
			mustExcludeResultCode: rules.GCPGKENodeServiceAccount,
		},
		{
			name: "defines service account in container node pool using reference",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
	node_config {
		service_account = google_service_account.service_account.email
	}
}
`,
			mustExcludeResultCode: rules.GCPGKENodeServiceAccount,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
