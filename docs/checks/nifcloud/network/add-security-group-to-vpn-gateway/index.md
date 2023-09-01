---
title: Missing security group for vpnGateway.
---

# Missing security group for vpnGateway.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Need to add a security group to your vpnGateway.

### Possible Impact
A security group controls the traffic that is allowed to reach and leave the resources that it is associated with.

### Suggested Resolution
Add security group for all vpnGateways


### Insecure Example

The following example will fail the nifcloud-network-add-security-group-to-vpn-gateway check.
```terraform

 resource "nifcloud_vpn_gateway" "bad_example" {
   security_group  = ""

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-network-add-security-group-to-vpn-gateway check.
```terraform

 resource "nifcloud_vpn_gateway" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/vpngw/change.htm](https://pfs.nifcloud.com/help/vpngw/change.htm){:target="_blank" rel="nofollow noreferrer noopener"}



