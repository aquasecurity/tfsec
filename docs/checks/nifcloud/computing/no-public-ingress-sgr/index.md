---
title: An ingress security group rule allows traffic from /0.
---

# An ingress security group rule allows traffic from /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
When publishing web applications, use a load balancer instead of publishing directly to instances.
		

### Possible Impact
Your port exposed to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the nifcloud-computing-no-public-ingress-sgr check.
```terraform

 resource "nifcloud_security_group_rule" "bad_example" {
 	type    = "IN"
 	cidr_ip = "0.0.0.0/0"
 }
 
```



### Secure Example

The following example will pass the nifcloud-computing-no-public-ingress-sgr check.
```terraform

 resource "nifcloud_security_group_rule" "good_example" {
 	type    = "IN"
 	cidr_ip = "10.0.0.0/16"
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#cidr_ip](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#cidr_ip){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/help/fw/rule_new.htm](https://pfs.nifcloud.com/help/fw/rule_new.htm){:target="_blank" rel="nofollow noreferrer noopener"}



