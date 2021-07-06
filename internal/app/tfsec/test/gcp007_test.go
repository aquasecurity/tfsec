package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_GkeLegacyMetadataEndpoints(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_container_cluster with metadata.disable-legacy-endpoints set to false",
			source: `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = false
  }
}`,
			mustIncludeResultCode: rules.GkeLegacyMetadataEndpoints,
		},
		{
			name: "check google_container_cluster with metadata.disable-legacy-endpoints set to true",
			source: `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = true
  }
}`,
			mustExcludeResultCode: rules.GkeLegacyMetadataEndpoints,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
