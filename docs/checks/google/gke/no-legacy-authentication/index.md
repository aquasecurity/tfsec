---
title: Legacy client authentication methods utilized.
---

# Legacy client authentication methods utilized.

### Default Severity: <span class="severity high">high</span>

### Explanation

It is recommended to use Service Accounts and OAuth as authentication methods for accessing the master in the container cluster. 

Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.

### Possible Impact
Username/password or certificate authentication methods are less secure

### Suggested Resolution
Use service account or OAuth for authentication


### Insecure Example

The following example will fail the google-gke-no-legacy-authentication check.
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
   master_auth {
     client_certificate_config {
       issue_client_certificate = true
     }
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

The following example will pass the google-gke-no-legacy-authentication check.
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


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_auth](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_auth){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods){:target="_blank" rel="nofollow noreferrer noopener"}



