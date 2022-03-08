---
title: Encryption for RDS Performance Insights should be enabled.
---

# Encryption for RDS Performance Insights should be enabled.

### Default Severity: <span class="severity high">high</span>

### Explanation

When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in `performance_insights_kms_key_id` references a KMS ARN

### Possible Impact
Data can be read from the RDS Performance Insights if it is compromised

### Suggested Resolution
Enable encryption for RDS clusters and instances


### Insecure Example

The following example will fail the aws-rds-enable-performance-insights-encryption check.
```terraform

resource "aws_rds_cluster_instance" "bad_example" {
	name = "bar"
	performance_insights_enabled = true
	performance_insights_kms_key_id = ""
}
		
```



### Secure Example

The following example will pass the aws-rds-enable-performance-insights-encryption check.
```terraform

resource "aws_rds_cluster_instance" "good_example" {
	name = "bar"
	performance_insights_enabled = true
	performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
		
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm){:target="_blank" rel="nofollow noreferrer noopener"}



