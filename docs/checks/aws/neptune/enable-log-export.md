---
title: Neptune logs export should be enabled
---

# Neptune logs export should be enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.

### Possible Impact
Limited visibility of audit trail for changes to Neptune

### Suggested Resolution
Enable export logs


### Insecure Example

The following example will fail the aws-neptune-enable-log-export check.
```terraform

 resource "aws_neptune_cluster" "bad_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = []
 }
 
```



### Secure Example

The following example will pass the aws-neptune-enable-log-export check.
```terraform

 resource "aws_neptune_cluster" "good_example" {
   cluster_identifier                  = "neptune-cluster-demo"
   engine                              = "neptune"
   backup_retention_period             = 5
   preferred_backup_window             = "07:00-09:00"
   skip_final_snapshot                 = true
   iam_database_authentication_enabled = true
   apply_immediately                   = true
   enable_cloudwatch_logs_exports      = ["audit"]
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#enable_cloudwatch_logs_exports](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#enable_cloudwatch_logs_exports){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html](https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html){:target="_blank" rel="nofollow noreferrer noopener"}



