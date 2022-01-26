---
title: Ensure MQ Broker is not publicly exposed
---

# Ensure MQ Broker is not publicly exposed

### Default Severity: <span class="severity high">high</span>

### Explanation

Public access of the MQ broker should be disabled and only allow routes to applications that require access.

### Possible Impact
Publicly accessible MQ Broker may be vulnerable to compromise

### Suggested Resolution
Disable public access when not required


### Insecure Example

The following example will fail the aws-mq-no-public-access check.
```terraform

 resource "aws_mq_broker" "bad_example" {
   broker_name = "example"
 
   configuration {
     id       = aws_mq_configuration.test.id
     revision = aws_mq_configuration.test.latest_revision
   }
 
   engine_type        = "ActiveMQ"
   engine_version     = "5.15.0"
   host_instance_type = "mq.t2.micro"
   security_groups    = [aws_security_group.test.id]
 
   user {
     username = "ExampleUser"
     password = "MindTheGap"
   }
   publicly_accessible = true
 }
 
```



### Secure Example

The following example will pass the aws-mq-no-public-access check.
```terraform

 resource "aws_mq_broker" "good_example" {
   broker_name = "example"
 
   configuration {
     id       = aws_mq_configuration.test.id
     revision = aws_mq_configuration.test.latest_revision
   }
 
   engine_type        = "ActiveMQ"
   engine_version     = "5.15.0"
   host_instance_type = "mq.t2.micro"
   security_groups    = [aws_security_group.test.id]
 
   user {
     username = "ExampleUser"
     password = "MindTheGap"
   }
   publicly_accessible = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#publicly_accessible](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#publicly_accessible){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility){:target="_blank" rel="nofollow noreferrer noopener"}



