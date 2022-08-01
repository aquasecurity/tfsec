---
title: An ingress Network ACL rule allows ALL ports.
---

# An ingress Network ACL rule allows ALL ports.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Ensure access to specific required ports is allowed, and nothing else.

### Possible Impact
All ports exposed for egressing data

### Suggested Resolution
Set specific allowed ports


### Insecure Example

The following example will fail the aws-ec2-no-excessive-port-access check.
```terraform

 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "all"
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 
```



### Secure Example

The following example will pass the aws-ec2-no-excessive-port-access check.
```terraform

 resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html){:target="_blank" rel="nofollow noreferrer noopener"}



