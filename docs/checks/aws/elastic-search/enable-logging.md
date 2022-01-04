---
title: enable-logging
---

### Explanation


AWS ES domain should have logging enabled by default.


### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for ElasticSearch domains


### Insecure Example

The following example will fail the aws-elastic-search-enable-logging check.

```terraform

resource "aws_elasticsearch_domain" "example" {
  // other config

  // One of the log_publishing_options has to be AUDIT_LOGS
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }
}

```



### Secure Example

The following example will pass the aws-elastic-search-enable-logging check.

```terraform

resource "aws_elasticsearch_domain" "example" {
  // other config

  // At minimum we should have AUDIT_LOGS enabled
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options){:target="_blank" rel="nofollow noreferrer noopener"}


