---
title: Elasticache Replication Group uses unencrypted traffic.
---

# Elasticache Replication Group uses unencrypted traffic.

### Default Severity: <span class="severity high">high</span>

### Explanation

Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.

### Possible Impact
In transit data in the Replication Group could be read if intercepted

### Suggested Resolution
Enable in transit encryption for replication group


### Insecure Example

The following example will fail the aws-elasticache-enable-in-transit-encryption check.
```terraform

 resource "aws_elasticache_replication_group" "bad_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
         transit_encryption_enabled = false
 }
 
```



### Secure Example

The following example will pass the aws-elasticache-enable-in-transit-encryption check.
```terraform

 resource "aws_elasticache_replication_group" "good_example" {
         replication_group_id = "foo"
         replication_group_description = "my foo cluster"
         transit_encryption_enabled = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



