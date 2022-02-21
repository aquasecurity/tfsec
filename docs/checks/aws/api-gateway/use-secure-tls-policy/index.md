---
title: API Gateway domain name uses outdated SSL/TLS protocols.
---

# API Gateway domain name uses outdated SSL/TLS protocols.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the aws-api-gateway-use-secure-tls-policy check.
```terraform

 resource "aws_api_gateway_domain_name" "bad_example" {
 	security_policy = "TLS_1_0"
 }
 
```



### Secure Example

The following example will pass the aws-api-gateway-use-secure-tls-policy check.
```terraform

 resource "aws_api_gateway_domain_name" "good_example" {
 	security_policy = "TLS_1_2"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html){:target="_blank" rel="nofollow noreferrer noopener"}



