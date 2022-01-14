package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
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
 }
 `},
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
   disk_encryption_key {
     kms_key_self_link = "something"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link",
		},
		Base: compute.CheckDiskEncryptionCustomerKey,
	})
}
