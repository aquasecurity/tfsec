package gke

import (
	"github.com/aquasecurity/defsec/rules"
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
     image_type = "something"
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
     image_type = "COS"
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#image_type",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_container_node_pool",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if imageTypeAttr := resourceBlock.GetBlock("node_config").GetAttribute("image_type"); imageTypeAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for node_config.image_type", ?)
			} else if imageTypeAttr.NotEqual("COS") {
				results.Add("Resource does not have node_config.image_type set to COS", imageTypeAttr)
			}
			return results
		},
	})
}
