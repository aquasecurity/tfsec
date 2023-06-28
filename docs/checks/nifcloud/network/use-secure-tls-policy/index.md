---
title: An outdated SSL policy is in use by a load balancer.
---

# An outdated SSL policy is in use by a load balancer.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
The SSL policy is outdated and has known vulnerabilities

### Suggested Resolution
Use a more recent TLS/SSL policy for the load balancer


### Insecure Example

The following example will fail the nifcloud-network-use-secure-tls-policy check.
```terraform

 resource "nifcloud_load_balancer" "bad_example" {
    load_balancer_port  = 443
    policy_type         = "standard"
    ssl_policy_name     = ""
 }
 
```



### Secure Example

The following example will pass the nifcloud-network-use-secure-tls-policy check.
```terraform

 resource "nifcloud_load_balancer" "good_example" {
    load_balancer_port  = 443
    policy_type         = "standard"
    ssl_policy_name     = "Standard Ciphers D ver1"
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_name](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_name){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer_listener#ssl_policy_name](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer_listener#ssl_policy_name){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/service/lb_l4.htm](https://pfs.nifcloud.com/service/lb_l4.htm){:target="_blank" rel="nofollow noreferrer noopener"}



