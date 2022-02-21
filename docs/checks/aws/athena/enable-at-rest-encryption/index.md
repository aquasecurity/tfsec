---
title: Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted
---

# Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted

### Default Severity: <span class="severity high">high</span>

### Explanation

Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.

### Possible Impact
Data can be read if the Athena Database is compromised

### Suggested Resolution
Enable encryption at rest for Athena databases and workgroup configurations


### Insecure Example

The following example will fail the aws-athena-enable-at-rest-encryption check.
```terraform

 resource "aws_athena_database" "bad_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 }
 
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
     }
   }
 }
 
```



### Secure Example

The following example will pass the aws-athena-enable-at-rest-encryption check.
```terraform

 resource "aws_athena_database" "good_example" {
   name   = "database_name"
   bucket = aws_s3_bucket.hoge.bucket
 
   encryption_configuration {
      encryption_option = "SSE_KMS"
      kms_key_arn       = aws_kms_key.example.arn
  }
 }
 
 resource "aws_athena_workgroup" "good_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = true
     publish_cloudwatch_metrics_enabled = true
 
     result_configuration {
       output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
 
       encryption_configuration {
         encryption_option = "SSE_KMS"
         kms_key_arn       = aws_kms_key.example.arn
       }
     }
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/athena/latest/ug/encryption.html](https://docs.aws.amazon.com/athena/latest/ug/encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



