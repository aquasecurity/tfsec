---
title: Enable Performance Insights to detect potential problems
---

# Enable Performance Insights to detect potential problems

### Default Severity: <span class="severity low">low</span>

### Explanation

Enabling Performance insights allows for greater depth in monitoring data.
		
For example, information about active sessions could help diagose a compromise or assist in the investigation

### Possible Impact
Without adequate monitoring, performance related issues may go unreported and potentially lead to compromise.

### Suggested Resolution
Enable performance insights


### Insecure Example

The following example will fail the aws-rds-enable-performance-insights check.
```terraform

resource "aws_rds_cluster_instance" "bad_example" {
	name = "bar"
	performance_insights_enabled = false
	performance_insights_kms_key_id = ""
}
		
```



### Secure Example

The following example will pass the aws-rds-enable-performance-insights check.
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

- [https://aws.amazon.com/rds/performance-insights/](https://aws.amazon.com/rds/performance-insights/){:target="_blank" rel="nofollow noreferrer noopener"}



