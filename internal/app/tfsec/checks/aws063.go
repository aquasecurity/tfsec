package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudtrailEnabledInAllRegions scanner.RuleCode = "AWS063"
const AWSCloudtrailEnabledInAllRegionsDescription scanner.RuleSummary = "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed"
const AWSCloudtrailEnabledInAllRegionsExplanation = `
When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.
`
const AWSCloudtrailEnabledInAllRegionsBadExample = `
resource "aws_cloudtrail" "bad_example" {
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
`
const AWSCloudtrailEnabledInAllRegionsGoodExample = `
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudtrailEnabledInAllRegions,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudtrailEnabledInAllRegionsDescription,
			Explanation: AWSCloudtrailEnabledInAllRegionsExplanation,
			BadExample:  AWSCloudtrailEnabledInAllRegionsBadExample,
			GoodExample: AWSCloudtrailEnabledInAllRegionsGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudtrail"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("is_multi_region_trail")  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not set multi region trail config.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			multiRegion := block.GetAttribute("is_multi_region_trail")
			if multiRegion.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' does not enable multi region trail.", block.FullName()),
						multiRegion.Range(),
						multiRegion,
						scanner.SeverityWarning,
						),
				}
			}/**/
			return nil
		},
	})
}
