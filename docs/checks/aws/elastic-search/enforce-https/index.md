---
title: Elasticsearch doesn't enforce HTTPS traffic.
---

# Elasticsearch doesn't enforce HTTPS traffic.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.

### Possible Impact
HTTP traffic can be intercepted and the contents read

### Suggested Resolution
Enforce the use of HTTPS for ElasticSearch


### Insecure Example

The following example will fail the aws-elastic-search-enforce-https check.
```terraform

 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = false
   }
 }
 
```



### Secure Example

The following example will pass the aws-elastic-search-enforce-https check.
```terraform

 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html){:target="_blank" rel="nofollow noreferrer noopener"}



