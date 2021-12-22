package gke

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/google/gke"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
 resource "google_service_account" "default" {
   account_id   = "service-account-id"
   display_name = "Service Account"
 }
 
 resource "google_container_cluster" "primary" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
 }
 
 resource "google_container_node_pool" "bad_example" {
   name       = "my-node-pool"
   cluster    = google_container_cluster.primary.id
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
   management {
     auto_upgrade = false
   }
 }
 `},
		GoodExample: []string{`
 resource "google_service_account" "default" {
   account_id   = "service-account-id"
   display_name = "Service Account"
 }
 
 resource "google_container_cluster" "primary" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
 }
 
 resource "google_container_node_pool" "good_example" {
   name       = "my-node-pool"
   cluster    = google_container_cluster.primary.id
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
   management {
     auto_upgrade = true
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_upgrade",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_container_node_pool",
		},
		Base: gke.CheckEnableAutoUpgrade,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if autoUpgradeAttr := resourceBlock.GetBlock("management").GetAttribute("auto_upgrade"); autoUpgradeAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for management.auto_upgrade", resourceBlock)
			} else if autoUpgradeAttr.IsFalse() {
				results.Add("Resource does not have management.auto_upgrade set to true", autoUpgradeAttr)
			}
			return results
		},
	})
}
