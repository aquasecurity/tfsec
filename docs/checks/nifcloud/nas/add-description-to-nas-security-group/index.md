---
title: Missing description for nas security group.
---

# Missing description for nas security group.

### Default Severity: <span class="severity low">low</span>

### Explanation

NAS security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing nas security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all nas security groups


### Insecure Example

The following example will fail the nifcloud-nas-add-description-to-nas-security-group check.
```terraform

 resource "nifcloud_nas_security_group" "bad_example" {
   name        = "app"
   description = ""
 }
 
```



### Secure Example

The following example will pass the nifcloud-nas-add-description-to-nas-security-group check.
```terraform

 resource "nifcloud_nas_security_group" "good_example" {
   group_name  = "app"
   description = "Allow from app traffic"
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#description](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#description){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/nas/fw_new.htm](https://pfs.nifcloud.com/help/nas/fw_new.htm){:target="_blank" rel="nofollow noreferrer noopener"}



