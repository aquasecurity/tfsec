---
title: encrypt-replication-group
---

### Explanation


You should ensure your Elasticache data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.


### Possible Impact
Data in the replication group could be readable if compromised

### Suggested Resolution
Enable encryption for replication group


### Insecure Example

The following example will fail the aws-elastic-search-encrypt-replication-group check.

```terraform

resource "aws_elasticache_replication_group" "bad_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        at_rest_encryption_enabled = false
}

```



### Secure Example

The following example will pass the aws-elastic-search-encrypt-replication-group check.

```terraform

resource "aws_elasticache_replication_group" "good_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        at_rest_encryption_enabled = true
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}


