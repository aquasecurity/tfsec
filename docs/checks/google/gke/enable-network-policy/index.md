---
title: Network Policy should be enabled on GKE clusters
---

# Network Policy should be enabled on GKE clusters

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Enabling a network policy allows the segregation of network traffic by namespace

### Possible Impact
Unrestricted inter-cluster communication

### Suggested Resolution
Enable network policy


### Insecure Example

The following example will fail the google-gke-enable-network-policy check.
```terraform

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
   network_policy {
     enabled = false
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
 
```



### Secure Example

The following example will pass the google-gke-enable-network-policy check.
```terraform

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
   network_policy {
     enabled = true
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
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enabled](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enabled){:target="_blank" rel="nofollow noreferrer noopener"}



