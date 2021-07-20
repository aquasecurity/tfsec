package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_GCPRawEncryptionKeySpecifiedForComputeDisk(t *testing.T) {
	expectedCode := "google-compute-disk-encryption-required"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Fails with raw key supplied",
			source: `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
	}
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Passes without raw key",
			source: `
resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
	}
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
