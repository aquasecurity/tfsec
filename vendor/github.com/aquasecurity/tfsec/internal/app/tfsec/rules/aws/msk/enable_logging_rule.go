package msk

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/msk"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `, `
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
       cloudwatch_logs {
         enabled   = false
         log_group = aws_cloudwatch_log_group.test.name
       }
       firehose {
         enabled         = true
         delivery_stream = aws_kinesis_firehose_delivery_stream.test_stream.name
       }
     }
   }
 
   tags = {
     foo = "bar"
   }
 }
 `, `
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
       cloudwatch_logs {
         enabled   = true
         log_group = aws_cloudwatch_log_group.test.name
       }
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_msk_cluster",
		},
		Base: msk.CheckEnableLogging,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			loggingBlock := resourceBlock.GetBlock("logging_info")
			if loggingBlock.IsNil() {
				results.Add("Resource does not have any broker logging enabled", resourceBlock)
				return
			}

			brokerBlock := loggingBlock.GetBlock("broker_logs")
			if brokerBlock.IsNil() {
				results.Add("Resource does not have any broker logging enabled", loggingBlock)
				return
			}

			if cloudwatchBlock := brokerBlock.GetBlock("cloudwatch_logs"); cloudwatchBlock.IsNotNil() {
				if cloudwatchBlock.GetAttribute("enabled").IsTrue() {
					return
				}
			}

			if firehoseBlock := brokerBlock.GetBlock("firehose"); firehoseBlock.IsNotNil() {
				if firehoseBlock.GetAttribute("enabled").IsTrue() {
					return
				}
			}

			if s3Block := brokerBlock.GetBlock("s3"); s3Block.IsNotNil() {
				if s3Block.GetAttribute("enabled").IsTrue() {
					return
				}
			}

			results.Add("Resource does not have any broker logging enabled", brokerBlock)
			return results
		},
	})
}
