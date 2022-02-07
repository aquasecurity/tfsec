---
title: S3 Buckets not publicly accessible through ACL.
---

# S3 Buckets not publicly accessible through ACL.

### Default Severity: <span class="severity high">high</span>

### Explanation


Buckets should not have ACLs that allow public access


### Possible Impact
Public access to the bucket can lead to data leakage

### Suggested Resolution
Don't use canned ACLs or switch to private acl


### Insecure Example

The following example will fail the aws-s3-no-public-access-with-acl check.
```terraform

resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}

```



### Secure Example

The following example will pass the aws-s3-no-public-access-with-acl check.
```terraform

resource "aws_s3_bucket" "good_example" {
	acl = "private"
}

```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html){:target="_blank" rel="nofollow noreferrer noopener"}



