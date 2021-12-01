---
title: set-minimum-password-length
---

### Explanation

IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.

### Possible Impact
Short, simple passwords are easier to compromise

### Suggested Resolution
Enforce longer, more complex passwords in the policy


### Insecure Example

The following example will fail the aws-iam-set-minimum-password-length check.

```terraform

resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# minimum_password_length not set
	# ...
}

```



### Secure Example

The following example will pass the aws-iam-set-minimum-password-length check.

```terraform

resource "aws_iam_account_password_policy" "good_example" {
	# ...
	minimum_password_length = 14
	# ...
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details){:target="_blank" rel="nofollow noreferrer noopener"}


