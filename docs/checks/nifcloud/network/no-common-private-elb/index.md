---
title: The elb has common private network
---

# The elb has common private network

### Default Severity: <span class="severity low">low</span>

### Explanation

When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.

### Possible Impact
The common private network is shared with other users

### Suggested Resolution
Use private LAN


### Insecure Example

The following example will fail the nifcloud-network-no-common-private-elb check.
```terraform

 resource "nifcloud_elb" "bad_example" {
   elb_name          = "foobar"
   availability_zone = "east-11"
   instance_port     = 80
   protocol          = "HTTP"
   lb_port           = 80

   network_interface {
     network_id = "net-COMMON_PRIVATE"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-network-no-common-private-elb check.
```terraform

 resource "nifcloud_elb" "good_example" {
   elb_name          = "foobar"
   availability_zone = "east-11"
   instance_port     = 80
   protocol          = "HTTP"
   lb_port           = 80

   network_interface {
     network_id = nifcloud_private_lan.main.id
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#network_id](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#network_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/service/plan.htm](https://pfs.nifcloud.com/service/plan.htm){:target="_blank" rel="nofollow noreferrer noopener"}



