---
title: EBS volumes must be encrypted
---

# EBS volumes must be encrypted

### Default Severity: <span class="severity high">high</span>

### Explanation

By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable encryption of EBS volumes


### Insecure Example

The following example will fail the aws-ebs-enable-volume-encryption check.
```terraform

 resource "aws_ebs_volume" "bad_example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
   encrypted = false
 }
 
```



### Secure Example

The following example will pass the aws-ebs-enable-volume-encryption check.
```terraform

 resource "aws_ebs_volume" "good_example" {
   availability_zone = "us-west-2a"
   size              = 40
 
   tags = {
     Name = "HelloWorld"
   }
   encrypted = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



