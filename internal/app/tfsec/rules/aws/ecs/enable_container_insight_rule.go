package ecs

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_cluster"},
		Base:           ecs.CheckEnableContainerInsight,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			settingsBlock := resourceBlock.GetBlocks("setting")
			for _, setting := range settingsBlock {
				if name := setting.GetAttribute("name"); name.IsNotNil() && name.Equals("containerinsights", block.IgnoreCase) {
					if valueAttr := setting.GetAttribute("value"); valueAttr.IsNotNil() {
						if !valueAttr.Equals("enabled", block.IgnoreCase) {
							results.Add("Resource has containerInsights set to disabled", valueAttr)
						}
						return
					}
				}
			}
			results.Add("Resource does not have containerInsights enabled", resourceBlock)
			return results
		},
	})
}
