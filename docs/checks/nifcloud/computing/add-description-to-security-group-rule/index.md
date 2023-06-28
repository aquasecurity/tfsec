---
title: Missing description for security group rule.
---

# Missing description for security group rule.

### Default Severity: <span class="severity low">low</span>

### Explanation

Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups rules


### Insecure Example

The following example will fail the nifcloud-computing-add-description-to-security-group-rule check.
```terraform

 resource "nifcloud_security_group_rule" "bad_example" {
   type        = "IN"
   description = ""
   from_port   = 80
   to_port     = 80
   protocol    = "TCP"
   cidr_ip     = nifcloud_private_lan.main.cidr_block
 }

 
```



### Secure Example

The following example will pass the nifcloud-computing-add-description-to-security-group-rule check.
```terraform

 resource "nifcloud_security_group_rule" "good_example" {
   type        = "IN"
   description = "HTTP from VPC"
   from_port   = 80
   to_port     = 80
   protocol    = "TCP"
   cidr_ip     = nifcloud_private_lan.main.cidr_block
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/fw/rule_new.htm](https://pfs.nifcloud.com/help/fw/rule_new.htm){:target="_blank" rel="nofollow noreferrer noopener"}



