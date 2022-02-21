---
title: Elasticsearch domain endpoint is using outdated TLS policy.
---

# Elasticsearch domain endpoint is using outdated TLS policy.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the aws-elastic-search-use-secure-tls-policy check.
```terraform

 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
   }
 }
 
```



### Secure Example

The following example will pass the aws-elastic-search-use-secure-tls-policy check.
```terraform

 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html){:target="_blank" rel="nofollow noreferrer noopener"}



