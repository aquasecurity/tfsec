---
title: AWS Classic resource usage.
---

# AWS Classic resource usage.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

### Possible Impact
Classic resources are running in a shared environment with other customers

### Suggested Resolution
Switch to VPC resources


### Insecure Example

The following example will fail the aws-rds-no-classic-resources check.
```terraform

 resource "aws_db_security_group" "bad_example" {
   # ...
 }
 
```



### Secure Example

The following example will pass the aws-rds-no-classic-resources check.
```terraform

 resource "aws_security_group" "good_example" {
   # ...
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html){:target="_blank" rel="nofollow noreferrer noopener"}



