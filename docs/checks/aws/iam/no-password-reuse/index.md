---
title: IAM Password policy should prevent password reuse.
---

# IAM Password policy should prevent password reuse.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.

### Possible Impact
Password reuse increase the risk of compromised passwords being abused

### Suggested Resolution
Prevent password reuse in the policy


### Insecure Example

The following example will fail the aws-iam-no-password-reuse check.
```terraform

 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	password_reuse_prevention = 1
 	# ...
 }
 			
```



### Secure Example

The following example will pass the aws-iam-no-password-reuse check.
```terraform

 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	password_reuse_prevention = 5
 	# ...
 }
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details){:target="_blank" rel="nofollow noreferrer noopener"}



