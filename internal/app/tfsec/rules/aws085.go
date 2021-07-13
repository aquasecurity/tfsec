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

const AWSConfigAggregatorCoveringAllRegions = "AWS085"
const AWSConfigAggregatorCoveringAllRegionsDescription = "Config configuration aggregator should be using all regions for source"
const AWSConfigAggregatorCoveringAllRegionsImpact = "Sources that aren't covered by the aggregator are not include in the configuration"
const AWSConfigAggregatorCoveringAllRegionsResolution = "Set the aggregator to cover all regions"
const AWSConfigAggregatorCoveringAllRegionsExplanation = `
The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.
`
const AWSConfigAggregatorCoveringAllRegionsBadExample = `
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  regions     = ["us-west-2", "eu-west-1"]
	}
}
`
const AWSConfigAggregatorCoveringAllRegionsGoodExample = `
resource "aws_config_configuration_aggregator" "good_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = true
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSConfigAggregatorCoveringAllRegions,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSConfigAggregatorCoveringAllRegionsDescription,
			Explanation: AWSConfigAggregatorCoveringAllRegionsExplanation,
			Impact:      AWSConfigAggregatorCoveringAllRegionsImpact,
			Resolution:  AWSConfigAggregatorCoveringAllRegionsResolution,
			BadExample:  AWSConfigAggregatorCoveringAllRegionsBadExample,
			GoodExample: AWSConfigAggregatorCoveringAllRegionsGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions",
				"https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_config_configuration_aggregator"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			aggBlock := resourceBlock.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
			if aggBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have account aggregation sources set", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			if aggBlock.MissingChild("all_regions") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have account aggregation sources to all regions", resourceBlock.FullName())).
						WithRange(aggBlock.Range()),
				)
				return
			}

			allRegionsAttr := aggBlock.GetAttribute("all_regions")
			if allRegionsAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has all_regions set to false", resourceBlock.FullName())).
						WithRange(allRegionsAttr.Range()).
						WithAttributeAnnotation(allRegionsAttr),
				)
			}

		},
	})
}
