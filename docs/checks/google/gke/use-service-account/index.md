---
title: Checks for service account defined for GKE nodes
---

# Checks for service account defined for GKE nodes

### Default Severity: <span class="severity medium">medium</span>

### Explanation

You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.

### Possible Impact
Service accounts with wide permissions can increase the risk of compromise

### Suggested Resolution
Use limited permissions for service accounts to be effective


### Insecure Example

The following example will fail the google-gke-use-service-account check.
```terraform

 resource "google_container_cluster" "bad_example" {
 	node_config {
 	}
 }
 
```



### Secure Example

The following example will pass the google-gke-use-service-account check.
```terraform

 resource "google_container_cluster" "good_example" {
 	node_config {
 		service_account = "cool-service-account@example.com"
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#service_account){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa){:target="_blank" rel="nofollow noreferrer noopener"}



