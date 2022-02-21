---
title: AWS SQS policy document has wildcard action statement.
---

# AWS SQS policy document has wildcard action statement.

### Default Severity: <span class="severity high">high</span>

### Explanation

SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.

### Possible Impact
SQS policies with wildcard actions allow more that is required

### Suggested Resolution
Keep policy scope to the minimum that is required to be effective


### Insecure Example

The following example will fail the aws-sqs-no-wildcards-in-policy-documents check.
```terraform

 resource "aws_sqs_queue_policy" "bad_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*"
     }
   ]
 }
 POLICY
 }
 
```



### Secure Example

The following example will pass the aws-sqs-no-wildcards-in-policy-documents check.
```terraform

 resource "aws_sqs_queue_policy" "good_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "sqs:SendMessage"
     }
   ]
 }
 POLICY
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html){:target="_blank" rel="nofollow noreferrer noopener"}



