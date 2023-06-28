---
title: The instance has common private network
---

# The instance has common private network

### Default Severity: <span class="severity low">low</span>

### Explanation

When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.

### Possible Impact
The common private network is shared with other users

### Suggested Resolution
Use private LAN


### Insecure Example

The following example will fail the nifcloud-computing-no-common-private-instance check.
```terraform

 resource "nifcloud_instance" "bad_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_PRIVATE"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-computing-no-common-private-instance check.
```terraform

 resource "nifcloud_instance" "good_example" {
   image_id        = data.nifcloud_image.ubuntu.id
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = nifcloud_private_lan.main.id
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#network_id](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#network_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/service/plan.htm](https://pfs.nifcloud.com/service/plan.htm){:target="_blank" rel="nofollow noreferrer noopener"}



