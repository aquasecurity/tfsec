---
title: IAM Password policy should have requirement for at least one number in the password.
---

# IAM Password policy should have requirement for at least one number in the password.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

IAM account password policies should ensure that passwords content including at least one number.

### Possible Impact
Short, simple passwords are easier to compromise

### Suggested Resolution
Enforce longer, more complex passwords in the policy


### Insecure Example

The following example will fail the aws-iam-require-numbers-in-passwords check.
```terraform

 resource "aws_iam_account_password_policy" "bad_example" {
 	# ...
 	# require_numbers not set
 	# ...
 }
 
```



### Secure Example

The following example will pass the aws-iam-require-numbers-in-passwords check.
```terraform

 resource "aws_iam_account_password_policy" "good_example" {
 	# ...
 	require_numbers = true
 	# ...
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details){:target="_blank" rel="nofollow noreferrer noopener"}



