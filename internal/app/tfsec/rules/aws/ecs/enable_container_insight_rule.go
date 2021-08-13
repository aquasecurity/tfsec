package ecs

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS090",
		Service:   "ecs",
		ShortCode: "enable-container-insight",
		Documentation: rule.RuleDocumentation{
			Summary: "ECS clusters should have container insights enabled",
			Explanation: `
Cloudwatch Container Insights provide more metrics and logs for container based applications and micro services.
`,
			Impact:     "Not all metrics and logs may be gathered for containers when Container Insights isn't enabled",
			Resolution: "Enable Container Insights",
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
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_cluster"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			settingsBlock := resourceBlock.GetBlocks("setting")
			for _, setting := range settingsBlock {
				if name := setting.GetAttribute("name"); name.IsNotNil() && name.Equals("containerinsights", block.IgnoreCase) {
					if valueAttr := setting.GetAttribute("value"); valueAttr.IsNotNil() {
						if !valueAttr.Equals("enabled", block.IgnoreCase) {
							set.AddResult().
								WithDescription("Resource '%s' has containerInsights set to disabled", resourceBlock.FullName()).
								WithAttribute(valueAttr)
						}
						return
					}
				}
			}
			set.AddResult().
				WithDescription("Resource '%s' does not have containerInsights enabled", resourceBlock.FullName())
		},
	})
}
