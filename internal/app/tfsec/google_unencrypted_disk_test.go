package tfsec

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GoogleUnencryptedDisk(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check google_compute_disk with no disk_encryption_key block",
			source: `
resource "google_compute_disk" "my-disk" {
	
}`,
			mustIncludeResultCode: google.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with empty disk_encryption_key block",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {}
}`,
			mustIncludeResultCode: google.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with raw key encryption",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		raw_key = "something"
	}
}`,
			mustExcludeResultCode: google.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with kms link",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}`,
			mustExcludeResultCode: google.GoogleUnencryptedDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
