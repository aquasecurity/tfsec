package compute

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 
   metadata = {
     block-project-ssh-keys = false
   }
 
   metadata_startup_script = "echo hi > /test.txt"
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = google_service_account.default.email
     scopes = ["cloud-platform"]
   }
 }
 `},
		GoodExample: []string{`
 resource "google_service_account" "default" {
   account_id   = "service_account_id"
   display_name = "Service Account"
 }
 
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   tags = ["foo", "bar"]
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 
   metadata = {
     block-project-ssh-keys = true
   }
 
   metadata_startup_script = "echo hi > /test.txt"
 
   service_account {
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     email  = google_service_account.default.email
     scopes = ["cloud-platform"]
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_instance",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			metadataAttr := resourceBlock.GetAttribute("metadata")
			val := metadataAttr.MapValue("block-project-ssh-keys")
			if val.Type() == cty.NilType {
				results.Add("Resource'%s' allows the use of project-wide SSH keys by default", resourceBlock)
				return
			}
			if val.Type() == cty.Bool && val.False() {
				results.Add("Resource'%s' explicitly allows the use of project-wide SSH keys by default", resourceBlock)
				return
			}
			return results
		},
	})
}
