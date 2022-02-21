---
title: S3 Data should be versioned
---

# S3 Data should be versioned

### Default Severity: <span class="severity medium">medium</span>

### Explanation


Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.


### Possible Impact
Deleted or modified data would not be recoverable

### Suggested Resolution
Enable versioning to protect against accidental/malicious removal or modification


### Insecure Example

The following example will fail the aws-s3-enable-versioning check.
```terraform

resource "aws_s3_bucket" "bad_example" {

}

```



### Secure Example

The following example will pass the aws-s3-enable-versioning check.
```terraform

resource "aws_s3_bucket" "good_example" {

	versioning {
		enabled = true
	}
}

```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html){:target="_blank" rel="nofollow noreferrer noopener"}



