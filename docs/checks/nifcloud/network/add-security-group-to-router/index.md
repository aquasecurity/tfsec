---
title: Missing security group for router.
---

# Missing security group for router.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Need to add a security group to your router.

### Possible Impact
A security group controls the traffic that is allowed to reach and leave the resources that it is associated with.

### Suggested Resolution
Add security group for all routers


### Insecure Example

The following example will fail the nifcloud-network-add-security-group-to-router check.
```terraform

 resource "nifcloud_router" "bad_example" {
   security_group  = ""

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-network-add-security-group-to-router check.
```terraform

 resource "nifcloud_router" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#security_group](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/router/change.htm](https://pfs.nifcloud.com/help/router/change.htm){:target="_blank" rel="nofollow noreferrer noopener"}



