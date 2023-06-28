---
title: An ingress db security group rule allows traffic from /0.
---

# An ingress db security group rule allows traffic from /0.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
Your port exposed to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the nifcloud-rdb-no-public-ingress-db-sgr check.
```terraform

 resource "nifcloud_db_security_group" "bad_example" {
   rule {
     cidr_ip = "0.0.0.0/0"
   }
 }
 
```



### Secure Example

The following example will pass the nifcloud-rdb-no-public-ingress-db-sgr check.
```terraform

 resource "nifcloud_db_security_group" "good_example" {
   rule {
     cidr_ip = "10.0.0.0/16"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/api/rdb/AuthorizeDBSecurityGroupIngress.htm](https://pfs.nifcloud.com/api/rdb/AuthorizeDBSecurityGroupIngress.htm){:target="_blank" rel="nofollow noreferrer noopener"}



