---
title: Missing description for security group.
---

# Missing description for security group.

### Default Severity: <span class="severity low">low</span>

### Explanation

Security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups


### Insecure Example

The following example will fail the nifcloud-computing-add-description-to-security-group check.
```terraform

 resource "nifcloud_security_group" "bad_example" {
   group_name  = "http"
   description = ""
 }
 
```



### Secure Example

The following example will pass the nifcloud-computing-add-description-to-security-group check.
```terraform

 resource "nifcloud_security_group" "good_example" {
   group_name  = "http"
   description = "Allow inbound HTTP traffic"
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/fw/change.htm](https://pfs.nifcloud.com/help/fw/change.htm){:target="_blank" rel="nofollow noreferrer noopener"}



