---
title: SNS topic not encrypted with CMK.
---

# SNS topic not encrypted with CMK.

### Default Severity: <span class="severity high">high</span>

### Explanation

Topics should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular key management.

### Possible Impact
Key management very limited when using default keys.

### Suggested Resolution
Use a CMK for SNS Topic encryption


### Insecure Example

The following example will fail the aws-sns-topic-encryption-use-cmk check.
```terraform

 resource "aws_sns_topic" "bad_example" {
    kms_master_key_id = "alias/aws/sns"
 }
 
```



### Secure Example

The following example will pass the aws-sns-topic-encryption-use-cmk check.
```terraform

 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



