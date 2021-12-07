---
title: Missing description for security group/security group rule.
shortcode: aws-vpc-add-decription-to-security-group
legacy: AWS018
summary: Missing description for security group/security group rule. 
resources: [aws_security_group aws_security_group_rule] 
permalink: /docs/aws/vpc/add-decription-to-security-group/
redirect_from: 
  - /docs/aws/AWS018/
---

### Explanation


Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.


### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups and rules


### Insecure Example

The following example will fail the aws-vpc-add-decription-to-security-group check.

```terraform

resource "aws_security_group" "bad_example" {
  name        = "http"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}

```



### Secure Example

The following example will pass the aws-vpc-add-decription-to-security-group check.

```terraform

resource "aws_security_group" "good_example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}

```



### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html](https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html){:target="_blank" rel="nofollow noreferrer noopener"}


