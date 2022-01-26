---
title: Stackdriver Monitoring should be enabled
---

# Stackdriver Monitoring should be enabled

### Default Severity: <span class="severity low">low</span>

### Explanation

StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.

### Possible Impact
Visibility will be reduced

### Suggested Resolution
Enable StackDriver monitoring


### Insecure Example

The following example will fail the google-gke-enable-stackdriver-monitoring check.
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
   monitoring_service = "monitoring.googleapis.com"
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

The following example will pass the google-gke-enable-stackdriver-monitoring check.
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
   monitoring_service = "monitoring.googleapis.com/kubernetes"
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


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#monitoring_service](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#monitoring_service){:target="_blank" rel="nofollow noreferrer noopener"}



