package config

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/config"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS085",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_config_configuration_aggregator"},
		Base:           config.CheckAggregateAllRegions,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			aggBlock := resourceBlock.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
			if aggBlock.IsNil() {
				results.Add("Resource should have account aggregation sources set", resourceBlock)
				return
			}

			if aggBlock.MissingChild("all_regions") {
				results.Add("Resource should have account aggregation sources to all regions", aggBlock)
				return
			}

			allRegionsAttr := aggBlock.GetAttribute("all_regions")
			if allRegionsAttr.IsFalse() {
				results.Add("Resource has all_regions set to false", allRegionsAttr)
			}

			return results
		},
	})
}
