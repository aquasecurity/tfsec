---
title: Task definition defines sensitive environment variable(s).
---

# Task definition defines sensitive environment variable(s).

### Default Severity: <span class="severity critical">critical</span>

### Explanation

You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.

### Possible Impact
Sensitive data could be exposed in the AWS Management Console

### Suggested Resolution
Use secrets for the task definition


### Insecure Example

The following example will fail the aws-ecs-no-plaintext-secrets check.
```terraform

 resource "aws_ecs_task_definition" "bad_example" {
   container_definitions = <<EOF
 [
   {
     "name": "my_service",
     "essential": true,
     "memory": 256,
     "environment": [
       { "name": "ENVIRONMENT", "value": "development" },
       { "name": "DATABASE_PASSWORD", "value": "oh no D:"}
     ]
   }
 ]
 EOF
 
 }
 
```



### Secure Example

The following example will pass the aws-ecs-no-plaintext-secrets check.
```terraform

 resource "aws_ecs_task_definition" "good_example" {
   container_definitions = <<EOF
 [
   {
     "name": "my_service",
     "essential": true,
     "memory": 256,
     "environment": [
       { "name": "ENVIRONMENT", "value": "development" }
     ]
   }
 ]
 EOF
 
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.vaultproject.io/](https://www.vaultproject.io/){:target="_blank" rel="nofollow noreferrer noopener"}



