package config

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSConfigAggregatorCoveringAllRegions(t *testing.T) {
	expectedCode := "aws-config-aggregate-all-regions"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Account aggregation not set fails check",
			source: `
 		resource "aws_config_configuration_aggregator" "bad_example" {
 			name = "example"
 		}
 		`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
