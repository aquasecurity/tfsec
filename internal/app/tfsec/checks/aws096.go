package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSECSTaskDefinitionEncryptionInTransit scanner.RuleCode = "AWS096"
const AWSECSTaskDefinitionEncryptionInTransitDescription scanner.RuleSummary = "ECS Task Definitions with EFS volumes should use in-transit encryption"
const AWSECSTaskDefinitionEncryptionInTransitImpact = "Intercepted traffic to and from EFS may lead to data loss"
const AWSECSTaskDefinitionEncryptionInTransitResolution = "Enable in transit encryption when using efs"
const AWSECSTaskDefinitionEncryptionInTransitExplanation = `
ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.
`
const AWSECSTaskDefinitionEncryptionInTransitBadExample = `
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
`
const AWSECSTaskDefinitionEncryptionInTransitGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSECSTaskDefinitionEncryptionInTransit,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSECSTaskDefinitionEncryptionInTransitDescription,
			Explanation: AWSECSTaskDefinitionEncryptionInTransitExplanation,
			Impact:      AWSECSTaskDefinitionEncryptionInTransitImpact,
			Resolution:  AWSECSTaskDefinitionEncryptionInTransitResolution,
			BadExample:  AWSECSTaskDefinitionEncryptionInTransitBadExample,
			GoodExample: AWSECSTaskDefinitionEncryptionInTransitGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption",
				"https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html",
				"https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("volume") {
				return nil
			}

			volumeBlocks := block.GetBlocks("volume")
			for _, v := range volumeBlocks {
				if v.MissingChild("efs_volume_configuration") {
					continue
				}
				efsConfigBlock := v.GetBlock("efs_volume_configuration")
				if efsConfigBlock.MissingChild("transit_encryption") {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' has efs configuration with in transit encryption implicitly disabled", block.FullName()),
							block.Range(),
							scanner.SeverityError,
						),
					}
				}
				transitAttr := efsConfigBlock.GetAttribute("transit_encryption")

				if transitAttr.Equals("disabled", parser.IgnoreCase) {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has efs configuration with transit encryption explicitly disabled", block.FullName()),
							transitAttr.Range(),
							transitAttr,
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
