---
title: Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed
---

# Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed

### Default Severity: <span class="severity medium">medium</span>

### Explanation

When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operating in.

### Possible Impact
Activity could be happening in your account in a different region

### Suggested Resolution
Enable Cloudtrail in all regions


### Insecure Example

The following example will fail the aws-cloudtrail-enable-all-regions check.
```terraform

 resource "aws_cloudtrail" "bad_example" {
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

The following example will pass the aws-cloudtrail-enable-all-regions check.
```terraform

 resource "aws_cloudtrail" "good_example" {
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



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html){:target="_blank" rel="nofollow noreferrer noopener"}



