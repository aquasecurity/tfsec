---
title: Cloudtrail log validation should be enabled to prevent tampering of log data
---

# Cloudtrail log validation should be enabled to prevent tampering of log data

### Default Severity: <span class="severity high">high</span>

### Explanation

Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.

### Possible Impact
Illicit activity could be removed from the logs

### Suggested Resolution
Turn on log validation for Cloudtrail


### Insecure Example

The following example will fail the aws-cloudtrail-enable-log-validation check.
```terraform

 resource "aws_cloudtrail" "bad_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 
```



### Secure Example

The following example will pass the aws-cloudtrail-enable-log-validation check.
```terraform

 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   enable_log_file_validation = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html){:target="_blank" rel="nofollow noreferrer noopener"}



