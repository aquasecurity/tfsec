package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GkeLegacyMetadataEndpoints(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_container_cluster with metadata.disable-legacy-endpoints set to false",
			source: `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = false
  }
}`,
			mustIncludeResultCode: google.GkeLegacyMetadataEndpoints,
		},
		{
			name: "check google_container_cluster with metadata.disable-legacy-endpoints set to true",
			source: `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = true
  }
}`,
			mustExcludeResultCode: google.GkeLegacyMetadataEndpoints,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
