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
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
     enable-oslogin = false
   }
 }
 `},
		GoodExample: []string{`
 resource "google_compute_instance" "default" {
   name         = "test"
   machine_type = "e2-medium"
   zone         = "us-central1-a"
 
   boot_disk {
     initialize_params {
       image = "debian-cloud/debian-9"
     }
   }
 
   // Local SSD disk
   scratch_disk {
     interface = "SCSI"
   }
 
   metadata = {
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
			val := metadataAttr.MapValue("enable-oslogin")
			if val.Type() == cty.Bool && val.False() {
				results.Add("Resource'%s' has OS Login disabled at instance-level", resourceBlock)
				return
			}
			return results
		},
	})
}
