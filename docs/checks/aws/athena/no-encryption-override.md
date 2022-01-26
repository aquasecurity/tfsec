---
title: Athena workgroups should enforce configuration to prevent client disabling encryption
---

# Athena workgroups should enforce configuration to prevent client disabling encryption

### Default Severity: <span class="severity high">high</span>

### Explanation

Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.

### Possible Impact
Clients can ignore encryption requirements

### Suggested Resolution
Enforce the configuration to prevent client overrides


### Insecure Example

The following example will fail the aws-athena-no-encryption-override check.
```terraform

 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
   configuration {
     enforce_workgroup_configuration    = false
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
 
 resource "aws_athena_workgroup" "bad_example" {
   name = "example"
 
 }
 
```



### Secure Example

The following example will pass the aws-athena-no-encryption-override check.
```terraform

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


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html](https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html){:target="_blank" rel="nofollow noreferrer noopener"}



