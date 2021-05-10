package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSConfigAggregatorCoveringAllRegions(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Account aggregation not set fails check",
			source: `
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
}
`,
			mustIncludeResultCode: checks.AWSConfigAggregatorCoveringAllRegions,
		},
		{
			name: "Account aggregation using specific regions fails check",
			source: `
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  regions     = ["us-west-2", "eu-west-1"]
	}
}
`,
			mustIncludeResultCode: checks.AWSConfigAggregatorCoveringAllRegions,
		}, {
			name: "All regions set to false fails check",
			source: `
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = false
	}
}
`,
			mustIncludeResultCode: checks.AWSConfigAggregatorCoveringAllRegions,
		},
		{
			name: "All regions set to true passes check",
			source: `
resource "aws_config_configuration_aggregator" "good_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = true
	}
}
`,
			mustExcludeResultCode: checks.AWSConfigAggregatorCoveringAllRegions,
		},
		{
			name: "All regions set to true passes check",
			source: `
resource "aws_config_configuration_aggregator" "good_example" {
	name = "example"
	  
	organization_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = true
	}
}
`,
			mustExcludeResultCode: checks.AWSConfigAggregatorCoveringAllRegions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
