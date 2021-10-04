package config

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
		LegacyID:  "AWS085",
		Service:   "config",
		ShortCode: "aggregate-all-regions",
		Documentation: rule.RuleDocumentation{
			Summary: "Config configuration aggregator should be using all regions for source",
			Explanation: `
The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.
`,
			Impact:     "Sources that aren't covered by the aggregator are not include in the configuration",
			Resolution: "Set the aggregator to cover all regions",
			BadExample: []string{`
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  regions     = ["us-west-2", "eu-west-1"]
	}
}
`},
			GoodExample: []string{`
resource "aws_config_configuration_aggregator" "good_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions",
				"https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_config_configuration_aggregator"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			aggBlock := resourceBlock.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
			if aggBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' should have account aggregation sources set", resourceBlock.FullName())
				return
			}

			if aggBlock.MissingChild("all_regions") {
				set.AddResult().
					WithDescription("Resource '%s' should have account aggregation sources to all regions", resourceBlock.FullName())
				return
			}

			allRegionsAttr := aggBlock.GetAttribute("all_regions")
			if allRegionsAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has all_regions set to false", resourceBlock.FullName()).
					WithAttribute(allRegionsAttr)
			}

		},
	})
}
