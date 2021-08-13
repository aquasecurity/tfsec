package cloudtrail

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
		LegacyID:  "AWS063",
		Service:   "cloudtrail",
		ShortCode: "enable-all-regions",
		Documentation: rule.RuleDocumentation{
			Summary:    "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed",
			Impact:     "Activity could be happening in your account in a different region",
			Resolution: "Enable Cloudtrail in all regions",
			Explanation: `
When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.
`,
			BadExample: []string{`
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
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudtrail"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("is_multi_region_trail") {
				set.AddResult().
					WithDescription("Resource '%s' does not set multi region trail config.", resourceBlock.FullName())
				return
			}

			multiRegionAttr := resourceBlock.GetAttribute("is_multi_region_trail")
			if multiRegionAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not enable multi region trail.", resourceBlock.FullName()).
					WithAttribute(multiRegionAttr)
			}
		},
	})
}
