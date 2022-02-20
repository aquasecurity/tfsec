---
title: OS Login should be enabled at project level
---

# OS Login should be enabled at project level

### Default Severity: <span class="severity medium">medium</span>

### Explanation

OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.

### Possible Impact
Access via SSH key cannot be revoked automatically when an IAM user is removed.

### Suggested Resolution
Enable OS Login at project level


### Insecure Example

The following example will fail the google-compute-project-level-oslogin check.
```terraform

 resource "google_compute_project_metadata" "default" {
   metadata = {
 	enable-oslogin = false
   }
 }
 
```



### Secure Example

The following example will pass the google-compute-project-level-oslogin check.
```terraform

 resource "google_compute_project_metadata" "default" {
   metadata = {
     enable-oslogin = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#){:target="_blank" rel="nofollow noreferrer noopener"}



