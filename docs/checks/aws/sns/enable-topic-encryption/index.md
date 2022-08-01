---
title: Unencrypted SNS topic.
---

# Unencrypted SNS topic.

### Default Severity: <span class="severity high">high</span>

### Explanation

Topics should be encrypted to protect their contents.

### Possible Impact
The SNS topic messages could be read if compromised

### Suggested Resolution
Turn on SNS Topic encryption


### Insecure Example

The following example will fail the aws-sns-enable-topic-encryption check.
```terraform

 resource "aws_sns_topic" "bad_example" {
 	# no key id specified
 }
 
```



### Secure Example

The following example will pass the aws-sns-enable-topic-encryption check.
```terraform

 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



