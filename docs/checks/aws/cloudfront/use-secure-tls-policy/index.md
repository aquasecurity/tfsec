---
title: CloudFront distribution uses outdated SSL/TLS protocols.
---

# CloudFront distribution uses outdated SSL/TLS protocols.

### Default Severity: <span class="severity high">high</span>

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
		
Note: that setting *minimum_protocol_version = "TLSv1.2_2021"* is only possible when *cloudfront_default_certificate* is false (eg. you are not using the cloudfront.net domain name). 
If *cloudfront_default_certificate* is true then the Cloudfront API will only allow setting *minimum_protocol_version = "TLSv1"*, and setting it to any other value will result in a perpetual diff in your *terraform plan*'s. 
The only option when using the cloudfront.net domain name is to ignore this rule.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the aws-cloudfront-use-secure-tls-policy check.
```terraform

 resource "aws_cloudfront_distribution" "bad_example" {
   viewer_certificate {
     cloudfront_default_certificate = aws_acm_certificate.example.arn
     minimum_protocol_version = "TLSv1.0"
   }
 }
 
```



### Secure Example

The following example will pass the aws-cloudfront-use-secure-tls-policy check.
```terraform

 resource "aws_cloudfront_distribution" "good_example" {
   viewer_certificate {
     cloudfront_default_certificate = aws_acm_certificate.example.arn
     minimum_protocol_version = "TLSv1.2_2021"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html){:target="_blank" rel="nofollow noreferrer noopener"}



