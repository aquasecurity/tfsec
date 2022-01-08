package ecs

import (
	"github.com/aquasecurity/defsec/rules/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS013",
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		Base:           ecs.CheckNoPlaintextSecrets,
	})
}
