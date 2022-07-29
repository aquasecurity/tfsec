---
title: EBS volume encryption should use Customer Managed Keys
---

# EBS volume encryption should use Customer Managed Keys

### Default Severity: <span class="severity low">low</span>

### Explanation

Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Enable encryption using customer managed keys


### Insecure Example

The following example will fail the aws-ec2-volume-encryption-customer-key check.
```terraform

 resource "aws_ebs_volume" "example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
 }
 
```



### Secure Example

The following example will pass the aws-ec2-volume-encryption-customer-key check.
```terraform

 resource "aws_kms_key" "ebs_encryption" {
 	enable_key_rotation = true
 }
 
 resource "aws_ebs_volume" "example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   kms_key_id = aws_kms_key.ebs_encryption.arn
 
   tags = {
     Name = "HelloWorld"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



