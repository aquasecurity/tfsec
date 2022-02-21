---
title: S3 Access block should block public ACL
---

# S3 Access block should block public ACL

### Default Severity: <span class="severity high">high</span>

### Explanation


S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.


### Possible Impact
PUT calls with public ACLs specified can make objects public

### Suggested Resolution
Enable blocking any PUT calls with a public ACL specified


### Insecure Example

The following example will fail the aws-s3-block-public-acls check.
```terraform

resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = aws_s3_bucket.bad_example.id
}
 
```



### Secure Example

The following example will pass the aws-s3-block-public-acls check.
```terraform

resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_public_access_block" "good_example" {
  bucket = aws_s3_bucket.good_example.id
  block_public_acls = true
}
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html){:target="_blank" rel="nofollow noreferrer noopener"}



