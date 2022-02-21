---
title: Ensure MSK Cluster logging is enabled
---

# Ensure MSK Cluster logging is enabled

### Default Severity: <span class="severity medium">medium</span>

### Explanation

Managed streaming for Kafka can log to Cloud Watch, Kinesis Firehose and S3, at least one of these locations should be logged to

### Possible Impact
Without logging it is difficult to trace issues

### Suggested Resolution
Enable logging


### Insecure Example

The following example will fail the aws-msk-enable-logging check.
```terraform

 resource "aws_msk_cluster" "example" {
   cluster_name           = "example"
   kafka_version          = "2.4.1"
   number_of_broker_nodes = 3
 
   broker_node_group_info {
     instance_type   = "kafka.m5.large"
     ebs_volume_size = 1000
     client_subnets = [
       aws_subnet.subnet_az1.id,
       aws_subnet.subnet_az2.id,
       aws_subnet.subnet_az3.id,
     ]
     security_groups = [aws_security_group.sg.id]
   }
   tags = {
     foo = "bar"
   }
 }
 
```



### Secure Example

The following example will pass the aws-msk-enable-logging check.
```terraform

 resource "aws_msk_cluster" "example" {
   cluster_name           = "example"
   kafka_version          = "2.4.1"
   number_of_broker_nodes = 3
 
   broker_node_group_info {
     instance_type   = "kafka.m5.large"
     ebs_volume_size = 1000
     client_subnets = [
       aws_subnet.subnet_az1.id,
       aws_subnet.subnet_az2.id,
       aws_subnet.subnet_az3.id,
     ]
     security_groups = [aws_security_group.sg.id]
   }
 
   logging_info {
     broker_logs {
       firehose {
         enabled         = false
         delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
       }
       s3 {
         enabled = true
         bucket  = aws_s3_bucket.bucket.id
         prefix  = "logs/msk-"
       }
     }
   }
 
   tags = {
     foo = "bar"
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html](https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html){:target="_blank" rel="nofollow noreferrer noopener"}



