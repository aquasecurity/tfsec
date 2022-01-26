---
title: ECR Repository should use customer managed keys to allow more control
---

# ECR Repository should use customer managed keys to allow more control

### Default Severity: <span class="severity low">low</span>

### Explanation

Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Use customer managed keys


### Insecure Example

The following example will fail the aws-ecr-repository-customer-key check.
```terraform

 resource "aws_ecr_repository" "bad_example" {
 	name                 = "bar"
 	image_tag_mutability = "MUTABLE"
   
 	image_scanning_configuration {
 	  scan_on_push = true
 	}
   }
 
```



### Secure Example

The following example will pass the aws-ecr-repository-customer-key check.
```terraform

 resource "aws_kms_key" "ecr_kms" {
 	enable_key_rotation = true
 }
 
 resource "aws_ecr_repository" "good_example" {
 	name                 = "bar"
 	image_tag_mutability = "MUTABLE"
   
 	image_scanning_configuration {
 	  scan_on_push = true
 	}
 
 	encryption_configuration {
 		encryption_type = "KMS"
 		kms_key = aws_kms_key.ecr_kms.key_id
 	}
   }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html){:target="_blank" rel="nofollow noreferrer noopener"}



