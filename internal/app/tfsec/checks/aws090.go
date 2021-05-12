package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSECSClusterContainerInsights scanner.RuleCode = "AWS090"
const AWSECSClusterContainerInsightsDescription scanner.RuleSummary = "ECS clusters should have container insights enabled"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSECSClusterContainerInsights,
		Documentation: scanner.CheckDocumentation{
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
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_ecs_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			settings := block.GetBlocks("setting")
			for _, setting := range settings {
				if name := setting.GetAttribute("name"); name.Equals("containerinsights", parser.IgnoreCase) {
					if setting.GetAttribute("value").Equals("enabled", parser.IgnoreCase) {
						return nil
					} else {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' has containerInsights set to disabled", block.FullName()),
								setting.Range(),
								setting.GetAttribute("value"),
								scanner.SeverityWarning,
							),
						}
					}
				}
			}
			return []scanner.Result{
				check.NewResult(
					fmt.Sprintf("Resoure '%s' does not have codeInsights enabled", block.FullName()),
					block.Range(),
					scanner.SeverityWarning,
				),
			}
		},
	})
}
