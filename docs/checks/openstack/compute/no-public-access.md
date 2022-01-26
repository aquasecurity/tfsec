---
title: A firewall rule allows traffic from/to the public internet
---

# A firewall rule allows traffic from/to the public internet

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
Exposure of infrastructure to the public internet

### Suggested Resolution
Employ more restrictive firewall rules


### Insecure Example

The following example will fail the openstack-compute-no-public-access check.
```terraform

 resource "openstack_fw_rule_v1" "rule_1" {
 	name             = "my_rule"
 	description      = "let anyone in"
 	action           = "allow"
 	protocol         = "tcp"
 	destination_port = "22"
 	enabled          = "true"
 }
 			
```



### Secure Example

The following example will pass the openstack-compute-no-public-access check.
```terraform

 resource "openstack_fw_rule_v1" "rule_1" {
 	name                   = "my_rule"
 	description            = "don't let just anyone in"
 	action                 = "allow"
 	protocol               = "tcp"
 	destination_ip_address = "10.10.10.1"
 	source_ip_address      = "10.10.10.2"
 	destination_port       = "22"
 	enabled                = "true"
 }
 			
```



### Links


- [https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1](https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1){:target="_blank" rel="nofollow noreferrer noopener"}



