---
title: enable-general-logging
---

### Explanation

Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation

### Possible Impact
Without logging it is difficult to trace issues

### Suggested Resolution
Enable general logging


### Insecure Example

The following example will fail the aws-mq-enable-general-logging check.

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
  logs {
    general = false
  }
}

```



### Secure Example

The following example will pass the aws-mq-enable-general-logging check.

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
  logs {
    general = true
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general){:target="_blank" rel="nofollow noreferrer noopener"}


