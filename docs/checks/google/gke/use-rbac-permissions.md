---
title: Legacy ABAC permissions are enabled.
---

# Legacy ABAC permissions are enabled.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.

RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.

### Possible Impact
ABAC permissions are less secure than RBAC permissions

### Suggested Resolution
Switch to using RBAC permissions


### Insecure Example

The following example will fail the google-gke-use-rbac-permissions check.
```terraform

 resource "google_container_cluster" "bad_example" {
 	enable_legacy_abac = "true"
 }
 
```



### Secure Example

The following example will pass the google-gke-use-rbac-permissions check.
```terraform

 resource "google_container_cluster" "good_example" {
 	# ...
 	# enable_legacy_abac not set
 	# ...
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_legacy_abac){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110){:target="_blank" rel="nofollow noreferrer noopener"}



