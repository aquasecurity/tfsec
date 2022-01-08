package ecs

import (
	"github.com/aquasecurity/defsec/rules/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS090",
		BadExample: []string{`
 resource "aws_ecs_cluster" "bad_example" {
   	name = "services-cluster"
 }
 `},
		GoodExample: []string{`
 resource "aws_ecs_cluster" "good_example" {
 	name = "services-cluster"
   
 	setting {
 	  name  = "containerInsights"
 	  value = "enabled"
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_cluster"},
		Base:           ecs.CheckEnableContainerInsight,
	})
}
