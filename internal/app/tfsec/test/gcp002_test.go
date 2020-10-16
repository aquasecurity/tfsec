package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_GoogleUnencryptedStorageBucket(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check google_storage_bucket with no encryption block",
			source: `
resource "google_storage_bucket" "my-bucket" {
	
}`,
			mustIncludeResultCode: checks.GoogleUnencryptedStorageBucket,
		},
		{
			name: "check google_storage_bucket with no encryption kms key name",
			source: `
resource "google_storage_bucket" "my-bucket" {
	encryption {}	
}`,
			mustExcludeResultCode: checks.GoogleUnencryptedStorageBucket,
		},
		{
			name: "check google_storage_bucket with non-empty encryption kms key name",
			source: `
resource "google_storage_bucket" "my-bucket" {
	encryption {
		default_kms_key_name = "my-key"
	}	
}`,
			mustExcludeResultCode: checks.GoogleUnencryptedStorageBucket,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
