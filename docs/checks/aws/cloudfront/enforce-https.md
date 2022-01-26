---
title: CloudFront distribution allows unencrypted (HTTP) communications.
---

# CloudFront distribution allows unencrypted (HTTP) communications.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.

### Possible Impact
CloudFront is available through an unencrypted connection

### Suggested Resolution
Only allow HTTPS for CloudFront distribution communication


### Insecure Example

The following example will fail the aws-cloudfront-enforce-https check.
```terraform

 resource "aws_cloudfront_distribution" "bad_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "allow-all"
 	  }
 }
 
```



### Secure Example

The following example will pass the aws-cloudfront-enforce-https check.
```terraform

 resource "aws_cloudfront_distribution" "good_example" {
 	default_cache_behavior {
 	    viewer_protocol_policy = "redirect-to-https"
 	  }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html){:target="_blank" rel="nofollow noreferrer noopener"}



