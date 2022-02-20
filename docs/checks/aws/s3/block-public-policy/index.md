---
title: S3 Access block should block public policy
---

# S3 Access block should block public policy

### Default Severity: <span class="severity high">high</span>

### Explanation


S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.


### Possible Impact
Users could put a policy that allows public access

### Suggested Resolution
Prevent policies that allow public access being PUT


### Insecure Example

The following example will fail the aws-s3-block-public-policy check.
```terraform

resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.example.id
}
 
resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.example.id 
  block_public_policy = false
}
 
```



### Secure Example

The following example will pass the aws-s3-block-public-policy check.
```terraform

resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.example.id 
  block_public_policy = true 
}
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html){:target="_blank" rel="nofollow noreferrer noopener"}



