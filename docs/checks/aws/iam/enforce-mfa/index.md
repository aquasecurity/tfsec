---
title: IAM Groups should have MFA enforcement activated.
---

# IAM Groups should have MFA enforcement activated.

### Default Severity: <span class="severity medium">medium</span>

### Explanation


IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			

### Possible Impact
User accounts are more vulnerable to compromise without multi factor authentication activated

### Suggested Resolution
Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced


### Insecure Example

The following example will fail the aws-iam-enforce-mfa check.
```terraform

data aws_caller_identity current {}
resource aws_iam_group developers {
  name =  "developers"
}

```



### Secure Example

The following example will pass the aws-iam-enforce-mfa check.
```terraform

resource "aws_iam_group" "support" {
  name =  "support"
}
resource aws_iam_group_policy mfa {
   
    group = aws_iam_group.support.name
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}
EOF
}

```



### Links


- [https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest](https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details){:target="_blank" rel="nofollow noreferrer noopener"}



