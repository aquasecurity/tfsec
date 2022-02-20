---
title: Service accounts should not have roles assigned with excessive privileges
---

# Service accounts should not have roles assigned with excessive privileges

### Default Severity: <span class="severity high">high</span>

### Explanation

Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.

### Possible Impact
Cloud account takeover if a resource using a service account is compromised

### Suggested Resolution
Limit service account access to minimal required set


### Insecure Example

The following example will fail the google-iam-no-privileged-service-accounts check.
```terraform

 resource "google_service_account" "test" {
   account_id   = "account123"
   display_name = "account123"
   email        = "jim@tfsec.dev"
 }
 
 resource "google_project_iam_member" "project" {
 	project = "your-project-id"
 	role    = "roles/owner"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 			
```



### Secure Example

The following example will pass the google-iam-no-privileged-service-accounts check.
```terraform

 resource "google_service_account" "test" {
 	account_id   = "account123"
 	display_name = "account123"
    email        = "jim@tfsec.dev"
 }
 
 resource "google_project_iam_member" "project" {
 	project = "your-project-id"
 	role    = "roles/logging.logWriter"
 	member  = "serviceAccount:${google_service_account.test.email}"
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/iam/docs/understanding-roles](https://cloud.google.com/iam/docs/understanding-roles){:target="_blank" rel="nofollow noreferrer noopener"}



