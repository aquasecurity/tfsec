package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP001",
		BadExample: []string{`
 resource "google_compute_disk" "bad_example" {
 	# ...
 }`},
		GoodExample: []string{`
 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		kms_key_self_link = "something"
 	}
 }
 
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk",
			"https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_compute_disk"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("disk_encryption_key") {
				results.Add("Resource defines a disk encrypted with an auto-generated key.", resourceBlock)
			}
			return results
		},
	})
}
