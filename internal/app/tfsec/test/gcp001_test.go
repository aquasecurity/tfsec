package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GoogleUnencryptedDisk(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check google_compute_disk with empty disk_encryption_key block",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {}
}`,
			mustIncludeResultCode: checks.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with raw key encryption",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		raw_key = "something"
	}
}`,
			mustExcludeResultCode: checks.GoogleUnencryptedDisk,
		},
		{
			name: "check google_compute_disk with kms link",
			source: `
resource "google_compute_disk" "my-disk" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}`,
			mustExcludeResultCode: checks.GoogleUnencryptedDisk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
