package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSECSTaskDefinitionEncryptionInTransit = "AWS096"
const AWSECSTaskDefinitionEncryptionInTransitDescription = "ECS Task Definitions with EFS volumes should use in-transit encryption"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSECSTaskDefinitionEncryptionInTransit,
		Documentation: rule.RuleDocumentation{
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
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_task_definition"},
		CheckFunc: func(set result.Set, b *block.Block, _ *hclcontext.Context) {

			if b.MissingChild("volume") {
			}

			volumeBlocks := b.GetBlocks("volume")
			for _, v := range volumeBlocks {
				if v.MissingChild("efs_volume_configuration") {
					continue
				}
				efsConfigBlock := v.GetBlock("efs_volume_configuration")
				if efsConfigBlock.MissingChild("transit_encryption") {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("Resource '%s' has efs configuration with in transit encryption implicitly disabled", b.FullName())).
							WithRange(b.Range()).
							WithSeverity(severity.Error),
					)
				}
				transitAttr := efsConfigBlock.GetAttribute("transit_encryption")

				if transitAttr.Equals("disabled", block.IgnoreCase) {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("Resource '%s' has efs configuration with transit encryption explicitly disabled", b.FullName())).
							WithRange(transitAttr.Range()).
							WithAttributeAnnotation(transitAttr).
							WithSeverity(severity.Error),
					)
				}
			}

		},
	})
}
