package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSConfigAggregatorCoveringAllRegions scanner.RuleCode = "AWS085"
const AWSConfigAggregatorCoveringAllRegionsDescription scanner.RuleSummary = "Config configuration aggregator should be using all regions for source"
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSConfigAggregatorCoveringAllRegions,
		Documentation: scanner.CheckDocumentation{
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
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_config_configuration_aggregator"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			aggBlock := block.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
			if aggBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have account aggregation sources set", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if aggBlock.MissingChild("all_regions") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have account aggregation sources to all regions", block.FullName()),
						aggBlock.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			allRegionsAttr := aggBlock.GetAttribute("all_regions")
			if allRegionsAttr.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has all_regions set to false", block.FullName()),
						allRegionsAttr.Range(),
						allRegionsAttr,
						scanner.SeverityWarning,
					),
				}
			}

			return nil
		},
	})
}
