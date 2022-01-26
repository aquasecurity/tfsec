---
title: S3 Access Block should Ignore Public Acl
---

# S3 Access Block should Ignore Public Acl

### Default Severity: <span class="severity high">high</span>

### Explanation


S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.


### Possible Impact
PUT calls with public ACLs specified can make objects public

### Suggested Resolution
Enable ignoring the application of public ACLs in PUT calls


### Insecure Example

The following example will fail the aws-s3-ignore-public-acls check.
```terraform

resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}


 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
 }
 
 resource "aws_s3_bucket_public_access_block" "bad_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = false
 }
 
```



### Secure Example

The following example will pass the aws-s3-ignore-public-acls check.
```terraform

resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

 resource "aws_s3_bucket_public_access_block" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
 	ignore_public_acls = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html){:target="_blank" rel="nofollow noreferrer noopener"}



