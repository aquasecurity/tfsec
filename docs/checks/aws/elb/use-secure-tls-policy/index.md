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

The following example will fail the aws-elb-use-secure-tls-policy check.
```terraform

 resource "aws_alb_listener" "bad_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
 	protocol = "HTTPS"
 }
 
```



### Secure Example

The following example will pass the aws-elb-use-secure-tls-policy check.
```terraform

 resource "aws_alb_listener" "good_example" {
 	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
 	protocol = "HTTPS"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener){:target="_blank" rel="nofollow noreferrer noopener"}



