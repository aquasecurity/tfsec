package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_GoogleUnencryptedDisk(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check google_compute_disk with empty disk_encryption_key block",
			source: `
resource "google_compute_disk" "my-disk" {
}`,
			mustIncludeResultCode: rules.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with raw key encryption",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		raw_key = "something"
	}
}`,
			mustExcludeResultCode: rules.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with kms link",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}`,
			mustExcludeResultCode: rules.GoogleUnencryptedDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
