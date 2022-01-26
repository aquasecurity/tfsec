---
title: IAM granted directly to user.
---

# IAM granted directly to user.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user. 

Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.

Permissions should be granted on roles, groups, services accounts instead.

### Possible Impact
Users shouldn't have permissions granted to them directly

### Suggested Resolution
Roles should be granted permissions and assigned to users


### Insecure Example

The following example will fail the google-iam-no-user-granted-permissions check.
```terraform

 resource "google_project_iam_binding" "bad_example" {
 	members = [
 		"user:test@example.com",
 		]
 }
 
 resource "google_project_iam_member" "bad_example" {
 	member = "user:test@example.com"
 }
 
```



### Secure Example

The following example will pass the google-iam-no-user-granted-permissions check.
```terraform

 resource "google_project_iam_binding" "good_example" {
 	members = [
 		"group:test@example.com",
 		]
 }
 
 resource "google_storage_bucket_iam_member" "good_example" {
 	member = "serviceAccount:test@example.com"
 }
```



### Links


- [https://www.terraform.io/docs/providers/google/d/iam_policy.html#members](https://www.terraform.io/docs/providers/google/d/iam_policy.html#members){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/iam/docs/overview#permissions](https://cloud.google.com/iam/docs/overview#permissions){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy){:target="_blank" rel="nofollow noreferrer noopener"}



