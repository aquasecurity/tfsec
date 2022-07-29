---
title: SQS queue should be encrypted with a CMK.
---

# SQS queue should be encrypted with a CMK.

### Default Severity: <span class="severity high">high</span>

### Explanation

Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.

### Possible Impact
The SQS queue messages could be read if compromised. Key management is very limited when using default keys.

### Suggested Resolution
Encrypt SQS Queue with a customer-managed key


### Insecure Example

The following example will fail the aws-sqs-queue-encryption-use-cmk check.
```terraform

 resource "aws_sqs_queue" "bad_example" {
	kms_master_key_id = "alias/aws/sqs"
 }
 
```



### Secure Example

The following example will pass the aws-sqs-queue-encryption-use-cmk check.
```terraform

 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



