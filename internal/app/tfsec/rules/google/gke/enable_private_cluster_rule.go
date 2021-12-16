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
 
 resource "google_container_cluster" "bad_example" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
   private_cluster_config {
     enable_private_nodes = false
   }
 }
 
 resource "google_container_node_pool" "primary_preemptible_nodes" {
   name       = "my-node-pool"
   location   = "us-central1"
   cluster    = google_container_cluster.primary.name
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes    = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
 }
 `},
		GoodExample: []string{`
 resource "google_service_account" "default" {
   account_id   = "service-account-id"
   display_name = "Service Account"
 }
 
 resource "google_container_cluster" "good_example" {
   name     = "my-gke-cluster"
   location = "us-central1"
 
   # We can't create a cluster with no node pool defined, but we want to only use
   # separately managed node pools. So we create the smallest possible default
   # node pool and immediately delete it.
   remove_default_node_pool = true
   initial_node_count       = 1
   private_cluster_config {
     enable_private_nodes = true
   }
 }
 
 resource "google_container_node_pool" "primary_preemptible_nodes" {
   name       = "my-node-pool"
   location   = "us-central1"
   cluster    = google_container_cluster.primary.name
   node_count = 1
 
   node_config {
     preemptible  = true
     machine_type = "e2-medium"
 
     # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
     service_account = google_service_account.default.email
     oauth_scopes    = [
       "https://www.googleapis.com/auth/cloud-platform"
     ]
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_private_nodes",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_container_cluster",
		},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if enablePrivateNodesAttr := resourceBlock.GetBlock("private_cluster_config").GetAttribute("enable_private_nodes"); enablePrivateNodesAttr.IsNil() { // alert on use of default value
				results.Add("Resource uses default value for private_cluster_config.enable_private_nodes", ?)
			} else if enablePrivateNodesAttr.IsFalse() {
				results.Add("Resource does not have private_cluster_config.enable_private_nodes set to true", enablePrivateNodesAttr)
			}
			return results
		},
	})
}
