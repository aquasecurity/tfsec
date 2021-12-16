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
 
   network_interface {
     network = "default"
 
     access_config {
       // Ephemeral IP
     }
   }
 }
 `},
		GoodExample: []string{`
 resource "google_compute_instance" "good_example" {
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
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#access_config",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_instance",
		},
		Base: compute.CheckInstancesDoNotHavePublicIPs,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if accessConfigBlock := resourceBlock.GetBlock("network_interface").GetBlock("access_config"); !accessConfigBlock.IsNil() {
				results.Add("Resource sets access_config", accessConfigBlock)
			}
			return results
		},
	})
}
