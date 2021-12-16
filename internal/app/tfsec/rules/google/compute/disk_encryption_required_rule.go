package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_disk"},
		Base:           compute.CheckDiskEncryptionRequired,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("disk_encryption_key") {
				return
			}

			if resourceBlock.MissingNestedChild("disk_encryption_key.raw_key") {
				return
			}

			rawKeyAttr := resourceBlock.GetNestedAttribute("disk_encryption_key.raw_key")

			if rawKeyAttr.IsString() {
				results.Add("Resource specifies an encryption key in raw format.", rawKeyAttr)
			}

			return results
		},
	})
}
