---
title: Ensure that Cloud Storage bucket is not anonymously or publicly accessible.
---

# Ensure that Cloud Storage bucket is not anonymously or publicly accessible.

### Default Severity: <span class="severity high">high</span>

### Explanation

Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.

### Possible Impact
Public exposure of sensitive data.

### Suggested Resolution
Restrict public access to the bucket.


### Insecure Example

The following example will fail the google-storage-no-public-access check.
```terraform

 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"allAuthenticatedUsers",
 	]
 }
 			
```



### Secure Example

The following example will pass the google-storage-no-public-access check.
```terraform

 resource "google_storage_bucket_iam_binding" "binding" {
 	bucket = google_storage_bucket.default.name
 	role = "roles/storage.admin"
 	members = [
 		"user:jane@example.com",
 	]
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b](https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b){:target="_blank" rel="nofollow noreferrer noopener"}



