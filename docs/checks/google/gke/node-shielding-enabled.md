---
title: Shielded GKE nodes not enabled.
---

# Shielded GKE nodes not enabled.

### Default Severity: <span class="severity high">high</span>

### Explanation

CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.

### Possible Impact
Node identity and integrity can't be verified without shielded GKE nodes

### Suggested Resolution
Enable node shielding


### Insecure Example

The following example will fail the google-gke-node-shielding-enabled check.
```terraform

 resource "google_container_cluster" "bad_example" {
 	enable_shielded_nodes = "false"
 }
```



### Secure Example

The following example will pass the google-gke-node-shielding-enabled check.
```terraform

 resource "google_container_cluster" "good_example" {
 	enable_shielded_nodes = "true"
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes){:target="_blank" rel="nofollow noreferrer noopener"}



