---
title: You should enable bucket access logging on the CloudTrail S3 bucket.
---

# You should enable bucket access logging on the CloudTrail S3 bucket.

### Default Severity: <span class="severity low">low</span>

### Explanation

Amazon S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed.

CIS recommends that you enable bucket access logging on the CloudTrail S3 bucket.

By enabling S3 bucket logging on target S3 buckets, you can capture all events that might affect objects in a target bucket. Configuring logs to be placed in a separate bucket enables access to log information, which can be useful in security and incident response workflows.


### Possible Impact
There is no way to determine the access to this bucket

### Suggested Resolution
Enable access logging on the bucket


### Insecure Example

The following example will fail the aws-cloudtrail-require-bucket-access-logging check.
```terraform

resource "aws_cloudtrail" "bad_example" {
   s3_bucket_name = "abcdefgh"
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
}

resource "aws_s3_bucket" "good_example" {
	bucket = "abcdefgh"
	
}
 
```



### Secure Example

The following example will pass the aws-cloudtrail-require-bucket-access-logging check.
```terraform

 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   s3_bucket_name = "abcdefgh"
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }

resource "aws_s3_bucket" "good_example" {
	bucket = "abcdefgh"
	logging {
		target_bucket = "target-bucket"
	}
}
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html){:target="_blank" rel="nofollow noreferrer noopener"}



