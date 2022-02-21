---
title: Redis cluster should have backup retention turned on
---

# Redis cluster should have backup retention turned on

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.

### Possible Impact
Without backups of the redis cluster recovery is made difficult

### Suggested Resolution
Configure snapshot retention for redis cluster


### Insecure Example

The following example will fail the aws-elasticache-enable-backup-retention check.
```terraform

 resource "aws_elasticache_cluster" "bad_example" {
 	cluster_id           = "cluster-example"
 	engine               = "redis"
 	node_type            = "cache.m4.large"
 	num_cache_nodes      = 1
 	parameter_group_name = "default.redis3.2"
 	engine_version       = "3.2.10"
 	port                 = 6379
 }
 
```



### Secure Example

The following example will pass the aws-elasticache-enable-backup-retention check.
```terraform

 resource "aws_elasticache_cluster" "good_example" {
 	cluster_id           = "cluster-example"
 	engine               = "redis"
 	node_type            = "cache.m4.large"
 	num_cache_nodes      = 1
 	parameter_group_name = "default.redis3.2"
 	engine_version       = "3.2.10"
 	port                 = 6379
 
 	snapshot_retention_limit = 5
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html){:target="_blank" rel="nofollow noreferrer noopener"}



