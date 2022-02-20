---
title: S3 buckets should each define an aws_s3_bucket_public_access_block
---

# S3 buckets should each define an aws_s3_bucket_public_access_block

### Default Severity: <span class="severity low">low</span>

### Explanation

The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.

### Possible Impact
Public access policies may be applied to sensitive data buckets

### Suggested Resolution
Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies


### Insecure Example

The following example will fail the aws-s3-specify-public-access-block check.
```terraform

 resource "aws_s3_bucket" "example" {
 	bucket = "example"
 	acl = "private-read"
 }
 
```



### Secure Example

The following example will pass the aws-s3-specify-public-access-block check.
```terraform

 resource "aws_s3_bucket" "example" {
 	bucket = "example"
 	acl = "private-read"
 }
   
 resource "aws_s3_bucket_public_access_block" "example" {
 	bucket = aws_s3_bucket.example.id
 	block_public_acls   = true
 	block_public_policy = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html){:target="_blank" rel="nofollow noreferrer noopener"}



