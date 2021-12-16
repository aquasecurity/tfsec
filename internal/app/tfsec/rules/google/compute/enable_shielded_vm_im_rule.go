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
 resource "google_compute_instance" "bad_example" {
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
 
   shielded_instance_config {
     enable_integrity_monitoring = false
   }
 }
 `},
		GoodExample: []string{`
 resource "google_compute_instance" "bad_example" {
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
 
   shielded_instance_config {
     enable_integrity_monitoring = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#enable_vtpm",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_instance",
		},
		Base: compute.CheckEnableShieldedVMIntegrityMonitoring,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if enableIMAttr := resourceBlock.GetBlock("shielded_instance_config").GetAttribute("enable_integrity_monitoring"); enableIMAttr.IsFalse() {
				results.Add("Resource has shielded_instance_config.enable_integrity_monitoring set to false", enableIMAttr)
			}
			return results
		},
	})
}
