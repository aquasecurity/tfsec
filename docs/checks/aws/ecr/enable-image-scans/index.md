---
title: ECR repository has image scans disabled.
---

# ECR repository has image scans disabled.

### Default Severity: <span class="severity high">high</span>

### Explanation

Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.

### Possible Impact
The ability to scan images is not being used and vulnerabilities will not be highlighted

### Suggested Resolution
Enable ECR image scanning


### Insecure Example

The following example will fail the aws-ecr-enable-image-scans check.
```terraform

 resource "aws_ecr_repository" "bad_example" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = false
   }
 }
 
```



### Secure Example

The following example will pass the aws-ecr-enable-image-scans check.
```terraform

 resource "aws_ecr_repository" "good_example" {
   name                 = "bar"
   image_tag_mutability = "MUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html){:target="_blank" rel="nofollow noreferrer noopener"}



