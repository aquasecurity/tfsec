---
title: ECR images tags shouldn't be mutable.
---

# ECR images tags shouldn't be mutable.

### Default Severity: <span class="severity high">high</span>

### Explanation

ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>

### Possible Impact
Image tags could be overwritten with compromised images

### Suggested Resolution
Only use immutable images in ECR


### Insecure Example

The following example will fail the aws-ecr-enforce-immutable-repository check.
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

The following example will pass the aws-ecr-enforce-immutable-repository check.
```terraform

 resource "aws_ecr_repository" "good_example" {
   name                 = "bar"
   image_tag_mutability = "IMMUTABLE"
 
   image_scanning_configuration {
     scan_on_push = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://sysdig.com/blog/toctou-tag-mutability/](https://sysdig.com/blog/toctou-tag-mutability/){:target="_blank" rel="nofollow noreferrer noopener"}



