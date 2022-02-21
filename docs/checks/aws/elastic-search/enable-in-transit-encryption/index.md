---
title: Elasticsearch domain uses plaintext traffic for node to node communication.
---

# Elasticsearch domain uses plaintext traffic for node to node communication.

### Default Severity: <span class="severity high">high</span>

### Explanation

Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.

### Possible Impact
In transit data between nodes could be read if intercepted

### Suggested Resolution
Enable encrypted node to node communication


### Insecure Example

The following example will fail the aws-elastic-search-enable-in-transit-encryption check.
```terraform

 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = false
   }
 }
 
```



### Secure Example

The following example will pass the aws-elastic-search-enable-in-transit-encryption check.
```terraform

 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html){:target="_blank" rel="nofollow noreferrer noopener"}



