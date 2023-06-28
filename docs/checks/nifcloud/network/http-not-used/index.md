---
title: Use of plain HTTP.
---

# Use of plain HTTP.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.

### Possible Impact
Your traffic is not protected

### Suggested Resolution
Switch to HTTPS to benefit from TLS security features


### Insecure Example

The following example will fail the nifcloud-network-http-not-used check.
```terraform

 resource "nifcloud_elb" "bad_example" {
     protocol = "HTTP"

     network_interface {
         network_id     = "net-COMMON_GLOBAL"
         is_vip_network = true
     }
 }
 
```



### Secure Example

The following example will pass the nifcloud-network-http-not-used check.
```terraform

 resource "nifcloud_elb" "good_example" {
     protocol = "HTTPS"
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#load_balancer_port){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/](https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/){:target="_blank" rel="nofollow noreferrer noopener"}



