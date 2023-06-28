---
title: Missing security group for instance.
---

# Missing security group for instance.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Need to add a security group to your instance.

### Possible Impact
A security group controls the traffic that is allowed to reach and leave the resources that it is associated with.

### Suggested Resolution
Add security group for all instances


### Insecure Example

The following example will fail the nifcloud-computing-add-security-group-to-instance check.
```terraform

 resource "nifcloud_instance" "bad_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = ""

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-computing-add-security-group-to-instance check.
```terraform

 resource "nifcloud_instance" "good_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#security_group](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/server/change_fw.htm](https://pfs.nifcloud.com/help/server/change_fw.htm){:target="_blank" rel="nofollow noreferrer noopener"}



