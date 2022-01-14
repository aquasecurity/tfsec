package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP013",
		BadExample: []string{`
 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
 	}
 }
 `},
		GoodExample: []string{`
 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link",
		},
		Base:           compute.CheckDiskEncryptionRequired,
	})
}
