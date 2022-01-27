---
title: Cloudfront distribution should have Access Logging configured
---

# Cloudfront distribution should have Access Logging configured

### Default Severity: <span class="severity medium">medium</span>

### Explanation

You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for CloudFront distributions


### Insecure Example

The following example will fail the aws-cloudfront-enable-logging check.
```terraform

 resource "aws_cloudfront_distribution" "bad_example" {
 	// other config
 	// no logging_config
 }
 
```



### Secure Example

The following example will pass the aws-cloudfront-enable-logging check.
```terraform

 resource "aws_cloudfront_distribution" "good_example" {
 	// other config
 	logging_config {
 		include_cookies = false
 		bucket          = "mylogs.s3.amazonaws.com"
 		prefix          = "myprefix"
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html){:target="_blank" rel="nofollow noreferrer noopener"}



