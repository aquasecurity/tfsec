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
		LegacyID: "AWS096",
		BadExample: []string{`
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
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption",
			"https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html",
			"https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		Base:           ecs.CheckEnableInTransitEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("volume") {
				return
			}

			volumeBlocks := resourceBlock.GetBlocks("volume")
			for _, v := range volumeBlocks {
				if v.MissingChild("efs_volume_configuration") {
					continue
				}
				efsConfigBlock := v.GetBlock("efs_volume_configuration")
				if efsConfigBlock.MissingChild("transit_encryption") {
					results.Add("Resource has efs configuration with in transit encryption implicitly disabled", efsConfigBlock)
					continue
				}
				transitAttr := efsConfigBlock.GetAttribute("transit_encryption")
				if transitAttr.Equals("disabled", block.IgnoreCase) {
					results.Add("Resource has efs configuration with transit encryption explicitly disabled", transitAttr)
				}
			}

			return results
		},
	})
}
