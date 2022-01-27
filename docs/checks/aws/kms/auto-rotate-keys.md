---
title: A KMS key is not configured to auto-rotate.
---

# A KMS key is not configured to auto-rotate.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

You should configure your KMS keys to auto rotate to maintain security and defend against compromise.

### Possible Impact
Long life KMS keys increase the attack surface when compromised

### Suggested Resolution
Configure KMS key to auto rotate


### Insecure Example

The following example will fail the aws-kms-auto-rotate-keys check.
```terraform

 resource "aws_kms_key" "bad_example" {
 	enable_key_rotation = false
 }
 
```



### Secure Example

The following example will pass the aws-kms-auto-rotate-keys check.
```terraform

 resource "aws_kms_key" "good_example" {
 	enable_key_rotation = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html){:target="_blank" rel="nofollow noreferrer noopener"}



