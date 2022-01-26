---
title: DocumentDB logs export should be enabled
---

# DocumentDB logs export should be enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.

### Possible Impact
Limited visibility of audit trail for changes to the DocumentDB

### Suggested Resolution
Enable export logs


### Insecure Example

The following example will fail the aws-documentdb-enable-log-export check.
```terraform

 resource "aws_docdb_cluster" "bad_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   enabled_cloudwatch_logs_exports = "something"
 }
 
```



### Secure Example

The following example will pass the aws-documentdb-enable-log-export check.
```terraform

 resource "aws_docdb_cluster" "good_example" {
   cluster_identifier      = "my-docdb-cluster"
   engine                  = "docdb"
   master_username         = "foo"
   master_password         = "mustbeeightchars"
   backup_retention_period = 5
   preferred_backup_window = "07:00-09:00"
   skip_final_snapshot     = true
   enabled_cloudwatch_logs_exports = "audit"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#enabled_cloudwatch_logs_exports](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#enabled_cloudwatch_logs_exports){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html](https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html){:target="_blank" rel="nofollow noreferrer noopener"}



