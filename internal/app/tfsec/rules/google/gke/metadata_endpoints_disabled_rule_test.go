package gke

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GkeLegacyMetadataEndpoints(t *testing.T) {
	expectedCode := "google-gke-metadata-endpoints-disabled"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check google_container_cluster with metadata.disable-legacy-endpoints set to true",
			source: `
resource "google_container_cluster" "gke" {
	metadata {
    disable-legacy-endpoints = true
  }
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
