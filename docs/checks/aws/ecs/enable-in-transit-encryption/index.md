---
title: ECS Task Definitions with EFS volumes should use in-transit encryption
---

# ECS Task Definitions with EFS volumes should use in-transit encryption

### Default Severity: <span class="severity high">high</span>

### Explanation

ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.

### Possible Impact
Intercepted traffic to and from EFS may lead to data loss

### Suggested Resolution
Enable in transit encryption when using efs


### Insecure Example

The following example will fail the aws-ecs-enable-in-transit-encryption check.
```terraform

 resource "aws_ecs_task_definition" "bad_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 
```



### Secure Example

The following example will pass the aws-ecs-enable-in-transit-encryption check.
```terraform

 resource "aws_ecs_task_definition" "good_example" {
 	family                = "service"
 	container_definitions = file("task-definitions/service.json")
   
 	volume {
 	  name = "service-storage"
   
 	  efs_volume_configuration {
 		file_system_id          = aws_efs_file_system.fs.id
 		root_directory          = "/opt/data"
 		transit_encryption      = "ENABLED"
 		transit_encryption_port = 2999
 		authorization_config {
 		  access_point_id = aws_efs_access_point.test.id
 		  iam             = "ENABLED"
 		}
 	  }
 	}
   }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html](https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html](https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html){:target="_blank" rel="nofollow noreferrer noopener"}



