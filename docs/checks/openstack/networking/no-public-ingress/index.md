---
title: A security group rule allows ingress traffic from multiple public addresses
---

# A security group rule allows ingress traffic from multiple public addresses

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
Exposure of infrastructure to the public internet

### Suggested Resolution
Employ more restrictive security group rules


### Insecure Example

The following example will fail the openstack-networking-no-public-ingress check.
```terraform

 resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "ingress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "0.0.0.0/0"
 }
 			
```



### Secure Example

The following example will pass the openstack-networking-no-public-ingress check.
```terraform

 resource "openstack_networking_secgroup_rule_v2" "rule_1" {
	direction         = "ingress"
	ethertype         = "IPv4"
	protocol          = "tcp"
	port_range_min    = 22
	port_range_max    = 22
	remote_ip_prefix  = "1.2.3.4/32"
 }
 			
```



### Links


- [https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1](https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1){:target="_blank" rel="nofollow noreferrer noopener"}



