package compute

import (
	"github.com/aquasecurity/defsec/rules/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
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
     serial-port-enable = true
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
     serial-port-enable = false
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
		Base: compute.CheckNoSerialPort,
	})
}
