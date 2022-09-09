---
title: CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs
---

# CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs

### Default Severity: <span class="severity low">low</span>

### Explanation


CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service.

CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs in a specified Amazon S3 bucket for long-term analysis, you can perform real-time analysis by configuring CloudTrail to send logs to CloudWatch Logs.

For a trail that is enabled in all Regions in an account, CloudTrail sends log files from all those Regions to a CloudWatch Logs log group.


### Possible Impact
Realtime log analysis is not available without enabling CloudWatch logging

### Suggested Resolution
Enable logging to CloudWatch


### Insecure Example

The following example will fail the aws-cloudtrail-ensure-cloudwatch-integration check.
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

The following example will pass the aws-cloudtrail-ensure-cloudwatch-integration check.
```terraform

 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.example.arn}:*" 

 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }

resource "aws_cloudwatch_log_group" "example" {
  name = "Example"
}
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console){:target="_blank" rel="nofollow noreferrer noopener"}



