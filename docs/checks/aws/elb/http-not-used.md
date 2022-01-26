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

The following example will fail the aws-elb-http-not-used check.
```terraform

 resource "aws_alb_listener" "bad_example" {
 	protocol = "HTTP"
 }
 
```



### Secure Example

The following example will pass the aws-elb-http-not-used check.
```terraform

 resource "aws_alb_listener" "good_example" {
 	protocol = "HTTPS"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/](https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/){:target="_blank" rel="nofollow noreferrer noopener"}



