---
title: Unencrypted S3 bucket.
---

### Default Severity: <span class="severity high">high</span>

### Explanation


S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.


### Possible Impact
The bucket objects could be read if compromised

### Suggested Resolution
Configure bucket encryption


### Insecure Example

The following example will fail the aws-s3-enable-bucket-encryption check.
```terraform

 resource "aws_s3_bucket" "bad_example" {
   bucket = "mybucket"
 }
 
```



### Secure Example

The following example will pass the aws-s3-enable-bucket-encryption check.
```terraform

 resource "aws_s3_bucket" "good_example" {
   bucket = "mybucket"
 
   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "arn"
         sse_algorithm     = "aws:kms"
       }
     }
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



