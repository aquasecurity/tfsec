---
title: Roles should not be assigned to default service accounts
---

# Roles should not be assigned to default service accounts

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Default service accounts should not be used - consider creating specialised service accounts for individual purposes.

### Possible Impact
Violation of principal of least privilege

### Suggested Resolution
Use specialised service accounts for specific purposes.


### Insecure Example

The following example will fail the google-iam-no-org-level-default-service-account-assignment check.
```terraform

 resource "google_organization_iam_member" "org-123" {
 	org_id = "organization-123"
 	role    = "roles/whatever"
 	member  = "123-compute@developer.gserviceaccount.com"
 }
 
```



### Secure Example

The following example will pass the google-iam-no-org-level-default-service-account-assignment check.
```terraform

 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
 }
 			  
 resource "google_organization_iam_member" "org-123" {
 	org_id = "org-123"
 	role    = "roles/whatever"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam){:target="_blank" rel="nofollow noreferrer noopener"}

- [](){:target="_blank" rel="nofollow noreferrer noopener"}

- [](){:target="_blank" rel="nofollow noreferrer noopener"}



