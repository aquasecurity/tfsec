---
title: CloudWatch log groups should be encrypted using CMK
---

# CloudWatch log groups should be encrypted using CMK

### Default Severity: <span class="severity low">low</span>

### Explanation

CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.

### Possible Impact
Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs.

### Suggested Resolution
Enable CMK encryption of CloudWatch Log Groups


### Insecure Example

The following example will fail the aws-cloudwatch-log-group-customer-key check.
```terraform

 resource "aws_cloudwatch_log_group" "bad_example" {
 	name = "bad_example"
 
 }
 
```



### Secure Example

The following example will pass the aws-cloudwatch-log-group-customer-key check.
```terraform

 resource "aws_cloudwatch_log_group" "good_example" {
 	name = "good_example"
 
 	kms_key_id = aws_kms_key.log_key.arn
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html){:target="_blank" rel="nofollow noreferrer noopener"}



