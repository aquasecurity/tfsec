---
title: Cloudtrail should be encrypted at rest to secure access to sensitive trail data
---

# Cloudtrail should be encrypted at rest to secure access to sensitive trail data

### Default Severity: <span class="severity high">high</span>

### Explanation

Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Enable encryption at rest


### Insecure Example

The following example will fail the aws-cloudtrail-enable-at-rest-encryption check.
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

The following example will pass the aws-cloudtrail-enable-at-rest-encryption check.
```terraform

 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   enable_log_file_validation = true
   kms_key_id = var.kms_id
 
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


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html){:target="_blank" rel="nofollow noreferrer noopener"}



