package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSECSClusterContainerInsights = "AWS090"
const AWSECSClusterContainerInsightsDescription = "ECS clusters should have container insights enabled"
const AWSECSClusterContainerInsightsImpact = "Not all metrics and logs may be gathered for containers when Container Insights isn't enabled"
const AWSECSClusterContainerInsightsResolution = "Enable Container Insights"
const AWSECSClusterContainerInsightsExplanation = `
Cloudwatch Container Insights provide more metrics and logs for container based applications and micro services.
`
const AWSECSClusterContainerInsightsBadExample = `
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"
}
`
const AWSECSClusterContainerInsightsGoodExample = `
resource "aws_ecs_cluster" "good_example" {
	name = "services-cluster"
  
	setting {
	  name  = "containerInsights"
	  value = "enabled"
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSECSClusterContainerInsights,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSECSClusterContainerInsightsDescription,
			Explanation: AWSECSClusterContainerInsightsExplanation,
			Impact:      AWSECSClusterContainerInsightsImpact,
			Resolution:  AWSECSClusterContainerInsightsResolution,
			BadExample:  AWSECSClusterContainerInsightsBadExample,
			GoodExample: AWSECSClusterContainerInsightsGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting",
				"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_cluster"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			settingsBlock := resourceBlock.GetBlocks("setting")
			for _, setting := range settingsBlock {
				if name := setting.GetAttribute("name"); name != nil && name.Equals("containerinsights", block.IgnoreCase) {
					if valueAttr := setting.GetAttribute("value"); valueAttr != nil {
						if !valueAttr.Equals("enabled", block.IgnoreCase) {
							set.Add(
								result.New(resourceBlock).
									WithDescription(fmt.Sprintf("Resource '%s' has containerInsights set to disabled", resourceBlock.FullName())).
									WithRange(setting.Range()).
									WithAttributeAnnotation(valueAttr),
							)
						}
						return
					}
				}
			}
			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' does not have containerInsights enabled", resourceBlock.FullName())).
					WithRange(resourceBlock.Range()),
			)
		},
	})
}
