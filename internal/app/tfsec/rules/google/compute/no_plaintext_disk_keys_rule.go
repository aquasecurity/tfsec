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
		BadExample: []string{`
 resource "google_compute_disk" "bad_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
   disk_encryption_key {
     raw_key = "something"
   }
 }
 `,
			`
resource "google_compute_instance" "default" {
  name         = "test"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
    disk_encryption_key_raw = "something"
  }

  scratch_disk {
    interface = "SCSI"
  }
}
 `,
		},
		GoodExample: []string{`
 resource "google_compute_disk" "good_example" {
   name  = "test-disk"
   type  = "pd-ssd"
   zone  = "us-central1-a"
   image = "debian-9-stretch-v20200805"
   labels = {
     environment = "dev"
   }
   physical_block_size_bytes = 4096
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#raw_key",
		},
		Base: compute.CheckDiskEncryptionRequired,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if rawKeyAttr := resourceBlock.GetBlock("disk_encryption_key").GetAttribute("raw_key"); rawKeyAttr.IsResolvable() {
				results.Add("Resource sets disk_encryption_key.raw_key", rawKeyAttr)
			}
			if diskEncryptionKeyRawAttr := resourceBlock.GetBlock("boot_disk").GetAttribute("disk_encryption_key_raw"); diskEncryptionKeyRawAttr.IsResolvable() {
				results.Add("Resource sets boot_disk.disk_encryption_key_raw", diskEncryptionKeyRawAttr)
			}
			return results
		},
	})
}
