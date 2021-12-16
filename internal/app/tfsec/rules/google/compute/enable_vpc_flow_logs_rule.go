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
 resource "google_compute_subnetwork" "bad_example" {
   name          = "test-subnetwork"
   ip_cidr_range = "10.2.0.0/16"
   region        = "us-central1"
   network       = google_compute_network.custom-test.id
   secondary_ip_range {
     range_name    = "tf-test-secondary-range-update1"
     ip_cidr_range = "192.168.10.0/24"
   }
   enable_flow_logs = false
 }
 
 resource "google_compute_network" "custom-test" {
   name                    = "test-network"
   auto_create_subnetworks = false
 }
 `},
		GoodExample: []string{`
 resource "google_compute_subnetwork" "good_example" {
   name          = "test-subnetwork"
   ip_cidr_range = "10.2.0.0/16"
   region        = "us-central1"
   network       = google_compute_network.custom-test.id
   secondary_ip_range {
     range_name    = "tf-test-secondary-range-update1"
     ip_cidr_range = "192.168.10.0/24"
   }
   enable_flow_logs = true
 }
 
 resource "google_compute_network" "custom-test" {
   name                    = "test-network"
   auto_create_subnetworks = false
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#enable_flow_logs",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_compute_subnetwork",
		},
		Base: compute.CheckEnableVPCFlowLogs,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if enableFlowLogsAttr := resourceBlock.GetAttribute("enable_flow_logs"); enableFlowLogsAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for enable_flow_logs", resourceBlock)
			} else if enableFlowLogsAttr.IsFalse() {
				results.Add("Resource does not have enable_flow_logs set to true", enableFlowLogsAttr)
			}
			return results
		},
	})
}
