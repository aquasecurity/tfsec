---
title: Users should not be granted service account access at the organization level
---

# Users should not be granted service account access at the organization level

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Users with service account access at organization level can impersonate any service account. Instead, they should be given access to particular service accounts as required.

### Possible Impact
Privilege escalation, impersonation of any/all services

### Suggested Resolution
Provide access at the service-level instead of organization-level, if required


### Insecure Example

The following example will fail the google-iam-no-org-level-service-account-impersonation check.
```terraform

 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/iam.serviceAccountUser"
 }
 
```



### Secure Example

The following example will pass the google-iam-no-org-level-service-account-impersonation check.
```terraform

 resource "google_organization_iam_binding" "organization-123" {
 	org_id  = "org-123"
 	role    = "roles/nothingInParticular"
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/iam/docs/impersonating-service-accounts](https://cloud.google.com/iam/docs/impersonating-service-accounts){:target="_blank" rel="nofollow noreferrer noopener"}



