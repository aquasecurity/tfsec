---
title: An ingress security group rule allows traffic from /0.
---

# An ingress security group rule allows traffic from /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
Your port exposed to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the aws-vpc-no-public-ingress-sgr check.
```terraform

 resource "aws_security_group_rule" "bad_example" {
 	type = "ingress"
 	cidr_blocks = ["0.0.0.0/0"]
 }
 
```



### Secure Example

The following example will pass the aws-vpc-no-public-ingress-sgr check.
```terraform

 resource "aws_security_group_rule" "good_example" {
 	type = "ingress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html){:target="_blank" rel="nofollow noreferrer noopener"}



