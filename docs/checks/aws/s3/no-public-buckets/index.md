---
title: S3 Access block should restrict public bucket to limit access
---

# S3 Access block should restrict public bucket to limit access

### Default Severity: <span class="severity high">high</span>

### Explanation

S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.

### Possible Impact
Public buckets can be accessed by anyone

### Suggested Resolution
Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)


### Insecure Example

The following example will fail the aws-s3-no-public-buckets check.
```terraform

resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	restrict_public_buckets = false
 }
 
```



### Secure Example

The following example will pass the aws-s3-no-public-buckets check.
```terraform

resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	restrict_public_buckets = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html){:target="_blank" rel="nofollow noreferrer noopener"}



