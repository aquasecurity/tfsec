---
title: Elasticache Replication Group stores unencrypted data at-rest.
---

# Elasticache Replication Group stores unencrypted data at-rest.

### Default Severity: <span class="severity high">high</span>

### Explanation

Data stored within an Elasticache replication node should be encrypted to ensure sensitive data is kept private.

### Possible Impact
At-rest data in the Replication Group could be compromised if accessed.

### Suggested Resolution
Enable at-rest encryption for replication group


### Insecure Example

The following example will fail the aws-elasticache-enable-at-rest-encryption check.
```terraform

 resource "aws_elasticache_replication_group" "bad_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = false
 }
 
```



### Secure Example

The following example will pass the aws-elasticache-enable-at-rest-encryption check.
```terraform

 resource "aws_elasticache_replication_group" "good_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
 
         at_rest_encryption_enabled = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



