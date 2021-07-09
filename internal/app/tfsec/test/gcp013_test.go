package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_GCPRawEncryptionKeySpecifiedForComputeDisk(t *testing.T) {

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
			mustIncludeResultCode: rules.GCPRawEncryptionKeySpecifiedForComputeDisk,
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
			mustExcludeResultCode: rules.GCPRawEncryptionKeySpecifiedForComputeDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
