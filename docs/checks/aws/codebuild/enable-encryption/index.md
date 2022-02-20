---
title: CodeBuild Project artifacts encryption should not be disabled
---

# CodeBuild Project artifacts encryption should not be disabled

### Default Severity: <span class="severity high">high</span>

### Explanation

All artifacts produced by your CodeBuild project pipeline should always be encrypted

### Possible Impact
CodeBuild project artifacts are unencrypted

### Suggested Resolution
Enable encryption for CodeBuild project artifacts


### Insecure Example

The following example will fail the aws-codebuild-enable-encryption check.
```terraform

 resource "aws_codebuild_project" "bad_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 
 		encryption_disabled = true
 	}
 }
 
 resource "aws_codebuild_project" "bad_example" {
 	// other config including primary artifacts
 
 	secondary_artifacts {
 		// other artifacts config
 		
 		encryption_disabled = false
 	}
 
 	secondary_artifacts {
 		// other artifacts config
 
 		encryption_disabled = true
 	}
 }
 
```



### Secure Example

The following example will pass the aws-codebuild-enable-encryption check.
```terraform

 resource "aws_codebuild_project" "good_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 
 		encryption_disabled = false
 	}
 }
 
 resource "aws_codebuild_project" "good_example" {
 	// other config
 
 	artifacts {
 		// other artifacts config
 	}
 }
 
 resource "aws_codebuild_project" "codebuild" {
 	// other config
 
 	secondary_artifacts {
 		// other artifacts config
 
 		encryption_disabled = false
 	}
 
 	secondary_artifacts {
 		// other artifacts config
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html){:target="_blank" rel="nofollow noreferrer noopener"}



