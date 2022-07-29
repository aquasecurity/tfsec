---
title: AWS best practice to not use the default VPC for workflows
---

# AWS best practice to not use the default VPC for workflows

### Default Severity: <span class="severity high">high</span>

### Explanation

Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.

### Possible Impact
The default VPC does not have critical security features applied

### Suggested Resolution
Create a non-default vpc for resources to be created in


### Insecure Example

The following example will fail the aws-ec2-no-default-vpc check.
```terraform

 resource "aws_default_vpc" "default" {
 	tags = {
 	  Name = "Default VPC"
 	}
   }
 
```



### Secure Example

The following example will pass the aws-ec2-no-default-vpc check.
```terraform

 # no aws default vpc present
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html](https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html){:target="_blank" rel="nofollow noreferrer noopener"}



