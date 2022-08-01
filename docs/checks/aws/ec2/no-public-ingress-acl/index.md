---
title: An ingress Network ACL rule allows specific ports from /0.
---

# An ingress Network ACL rule allows specific ports from /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
The ports are exposed for ingressing data to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the aws-ec2-no-public-ingress-acl check.
```terraform

 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 
```



### Secure Example

The following example will pass the aws-ec2-no-public-ingress-acl check.
```terraform

 resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "10.0.0.0/16"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html){:target="_blank" rel="nofollow noreferrer noopener"}



