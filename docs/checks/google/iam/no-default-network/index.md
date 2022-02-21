---
title: Default network should not be created at project level
---

# Default network should not be created at project level

### Default Severity: <span class="severity high">high</span>

### Explanation

The default network which is provided for a project contains multiple insecure firewall rules which allow ingress to the project's infrastructure. Creation of this network should therefore be disabled.

### Possible Impact
Exposure of internal infrastructure/services to public internet

### Suggested Resolution
Disable automatic default network creation


### Insecure Example

The following example will fail the google-iam-no-default-network check.
```terraform

 resource "google_project" "bad_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = true
 }
 
```



### Secure Example

The following example will pass the google-iam-no-default-network check.
```terraform

 resource "google_project" "good_example" {
   name       = "My Project"
   project_id = "your-project-id"
   org_id     = "1234567"
   auto_create_network = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project#auto_create_network](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project#auto_create_network){:target="_blank" rel="nofollow noreferrer noopener"}



