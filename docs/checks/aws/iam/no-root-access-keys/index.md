---
title: The root user has complete access to all services and resources in an AWS account. AWS Access Keys provide programmatic access to a given account.
---

# The root user has complete access to all services and resources in an AWS account. AWS Access Keys provide programmatic access to a given account.

### Default Severity: <span class="severity critical">critical</span>

### Explanation


CIS recommends that all access keys be associated with the root user be removed. Removing access keys associated with the root user limits vectors that the account can be compromised by. Removing the root user access keys also encourages the creation and use of role-based accounts that are least privileged.
			

### Possible Impact
Compromise of the root account compromises the entire AWS account and all resources within it.

### Suggested Resolution
Use lower privileged accounts instead, so only required privileges are available.


### Insecure Example

The following example will fail the aws-iam-no-root-access-keys check.
```terraform

resource "aws_iam_access_key" "good_example" {
 	user = "root"
}
 			
```



### Secure Example

The following example will pass the aws-iam-no-root-access-keys check.
```terraform

resource "aws_iam_access_key" "good_example" {
 	user = "lowprivuser"
}
 			
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html){:target="_blank" rel="nofollow noreferrer noopener"}



