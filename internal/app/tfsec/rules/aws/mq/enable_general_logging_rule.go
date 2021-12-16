package mq

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/mq"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general",
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_mq_broker",
		},
		Base: mq.CheckEnableGeneralLogging,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			if logsBlock := resourceBlock.GetBlock("logs"); logsBlock.IsNil() {
				results.Add("Resource uses default value for logs.general", resourceBlock)
			} else if generalAttr := logsBlock.GetAttribute("general"); generalAttr.IsNil() {
				results.Add("Resource uses default value for logs.general", logsBlock)
			} else if generalAttr.IsFalse() {
				results.Add("Resource does not have logs.general set to true", generalAttr)
			}
			return results
		},
	})
}
