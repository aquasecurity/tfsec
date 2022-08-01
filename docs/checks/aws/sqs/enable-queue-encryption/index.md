---
title: Unencrypted SQS queue.
---

# Unencrypted SQS queue.

### Default Severity: <span class="severity high">high</span>

### Explanation

Queues should be encrypted to protect queue contents.

### Possible Impact
The SQS queue messages could be read if compromised

### Suggested Resolution
Turn on SQS Queue encryption


### Insecure Example

The following example will fail the aws-sqs-enable-queue-encryption check.
```terraform

 resource "aws_sqs_queue" "bad_example" {
 	# no key specified
 }
 
```



### Secure Example

The following example will pass the aws-sqs-enable-queue-encryption check.
```terraform

 resource "aws_sqs_queue" "good_example" {
 	kms_master_key_id = "/blah"
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html){:target="_blank" rel="nofollow noreferrer noopener"}



