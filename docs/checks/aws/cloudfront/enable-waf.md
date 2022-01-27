---
title: CloudFront distribution does not have a WAF in front.
---

# CloudFront distribution does not have a WAF in front.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.

### Possible Impact
Complex web application attacks can more easily be performed without a WAF

### Suggested Resolution
Enable WAF for the CloudFront distribution


### Insecure Example

The following example will fail the aws-cloudfront-enable-waf check.
```terraform

 resource "aws_cloudfront_distribution" "bad_example" {
   origin_group {
     origin_id = "groupS3"
 
     failover_criteria {
       status_codes = [403, 404, 500, 502]
     }
 
     member {
       origin_id = "primaryS3"
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 }
 
```



### Secure Example

The following example will pass the aws-cloudfront-enable-waf check.
```terraform

 resource "aws_cloudfront_distribution" "good_example" {
 
   origin {
     domain_name = aws_s3_bucket.primary.bucket_regional_domain_name
     origin_id   = "primaryS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   origin {
     domain_name = aws_s3_bucket.failover.bucket_regional_domain_name
     origin_id   = "failoverS3"
 
     s3_origin_config {
       origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
     }
   }
 
   default_cache_behavior {
     target_origin_id = "groupS3"
   }
 
   web_acl_id = "waf_id"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#web_acl_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html](https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html){:target="_blank" rel="nofollow noreferrer noopener"}



