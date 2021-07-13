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

const AWSCloudtrailEnabledInAllRegions = "AWS063"
const AWSCloudtrailEnabledInAllRegionsDescription = "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed"
const AWSCloudtrailEnabledInAllRegionsImpact = "Activity could be happening in your account in a different region"
const AWSCloudtrailEnabledInAllRegionsResolution = "Enable Cloudtrail in all regions"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudtrailEnabledInAllRegions,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSCloudtrailEnabledInAllRegionsDescription,
			Impact:      AWSCloudtrailEnabledInAllRegionsImpact,
			Resolution:  AWSCloudtrailEnabledInAllRegionsResolution,
			Explanation: AWSCloudtrailEnabledInAllRegionsExplanation,
			BadExample:  AWSCloudtrailEnabledInAllRegionsBadExample,
			GoodExample: AWSCloudtrailEnabledInAllRegionsGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudtrail"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("is_multi_region_trail") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not set multi region trail config.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			multiRegionAttr := resourceBlock.GetAttribute("is_multi_region_trail")
			if multiRegionAttr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not enable multi region trail.", resourceBlock.FullName())).
						WithRange(multiRegionAttr.Range()).
						WithAttributeAnnotation(multiRegionAttr),
				)
			}
		},
	})
}
