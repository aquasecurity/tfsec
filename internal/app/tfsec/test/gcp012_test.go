package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GCPGKENodeServiceAccount(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
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
			mustIncludeResultCode: checks.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define service account in container cluster but removes default node pool",
			source: `
resource "google_container_cluster" "my-cluster" {
	remove_default_node_pool = true
}
`,
			mustExcludeResultCode: checks.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define node_config in container cluster and uses default node pool",
			source: `
resource "google_container_cluster" "my-cluster" {
}
`,
			mustIncludeResultCode: checks.GCPGKENodeServiceAccount,
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
			mustExcludeResultCode: checks.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define service account in container node pool",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
	node_config {
	}
}
`,
			mustIncludeResultCode: checks.GCPGKENodeServiceAccount,
		},
		{
			name: "does not define node_config in container node pool",
			source: `
resource "google_container_node_pool" "my-np-cluster" {
}
`,
			mustIncludeResultCode: checks.GCPGKENodeServiceAccount,
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
			mustExcludeResultCode: checks.GCPGKENodeServiceAccount,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
