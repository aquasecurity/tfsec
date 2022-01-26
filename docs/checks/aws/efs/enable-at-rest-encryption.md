---
title: EFS Encryption has not been enabled
---

# EFS Encryption has not been enabled

### Default Severity: <span class="severity high">high</span>

### Explanation

If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

### Possible Impact
Data can be read from the EFS if compromised

### Suggested Resolution
Enable encryption for EFS


### Insecure Example

The following example will fail the aws-efs-enable-at-rest-encryption check.
```terraform

 resource "aws_efs_file_system" "bad_example" {
   name       = "bar"
   encrypted  = false
   kms_key_id = ""
 }
```



### Secure Example

The following example will pass the aws-efs-enable-at-rest-encryption check.
```terraform

 resource "aws_efs_file_system" "good_example" {
   name       = "bar"
   encrypted  = true
   kms_key_id = "my_kms_key"
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/efs/latest/ug/encryption.html](https://docs.aws.amazon.com/efs/latest/ug/encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



