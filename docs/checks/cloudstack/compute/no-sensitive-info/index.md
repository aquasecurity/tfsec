---
title: No sensitive data stored in user_data
---

# No sensitive data stored in user_data

### Default Severity: <span class="severity high">high</span>

### Explanation

When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information

### Possible Impact
Sensitive credentials in the user data can be leaked

### Suggested Resolution
Don't use sensitive data in the user data section


### Insecure Example

The following example will fail the cloudstack-compute-no-sensitive-info check.
```terraform

 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = <<EOF
 export DATABASE_PASSWORD=\"SomeSortOfPassword\"
 EOF
 }
 
```



### Secure Example

The following example will pass the cloudstack-compute-no-sensitive-info check.
```terraform

 resource "cloudstack_instance" "web" {
   name             = "server-1"
   service_offering = "small"
   network_id       = "6eb22f91-7454-4107-89f4-36afcdf33021"
   template         = "CentOS 6.5"
   zone             = "zone-1"
   user_data        = <<EOF
 export GREETING="Hello there"
 EOF
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/cloudstack/latest/docs/resources/instance#](https://registry.terraform.io/providers/hashicorp/cloudstack/latest/docs/resources/instance#){:target="_blank" rel="nofollow noreferrer noopener"}



