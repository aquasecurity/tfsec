---
title: Missing description for security group.
---

# Missing description for security group.

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Security groups should include a description for auditing purposes. Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Auditing capability and awareness limited.

### Suggested Resolution
Add descriptions for all security groups


### Insecure Example

The following example will fail the openstack-networking-describe-security-group check.
```terraform

 resource "openstack_networking_secgroup_v2" "group_1" {
 }
 			
```



### Secure Example

The following example will pass the openstack-networking-describe-security-group check.
```terraform

 resource "openstack_networking_secgroup_v2" "group_1" {
 	description            = "don't let just anyone in"
 }
 			
```




