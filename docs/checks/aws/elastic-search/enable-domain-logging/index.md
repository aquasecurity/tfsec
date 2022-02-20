---
title: Domain logging should be enabled for Elastic Search domains
---

# Domain logging should be enabled for Elastic Search domains

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Amazon ES exposes four Elasticsearch logs through Amazon CloudWatch Logs: error logs, search slow logs, index slow logs, and audit logs. 

Search slow logs, index slow logs, and error logs are useful for troubleshooting performance and stability issues. 

Audit logs track user activity for compliance purposes. 

All the logs are disabled by default.

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for ElasticSearch domains


### Insecure Example

The following example will fail the aws-elastic-search-enable-domain-logging check.
```terraform

 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 }
 
```



### Secure Example

The following example will pass the aws-elastic-search-enable-domain-logging check.
```terraform

 resource "aws_elasticsearch_domain" "good_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = true  
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html){:target="_blank" rel="nofollow noreferrer noopener"}



