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
		LegacyID:  "AWS064",
		Service:   "cloudtrail",
		ShortCode: "enable-log-validation",
		Documentation: rule.RuleDocumentation{
			Summary:    "Cloudtrail log validation should be enabled to prevent tampering of log data",
			Impact:     "Illicit activity could be removed from the logs",
			Resolution: "Turn on log validation for Cloudtrail",
			Explanation: `
Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.
`,
			BadExample: []string{`
resource "aws_cloudtrail" "bad_example" {
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
			GoodExample: []string{`
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail = true
  enable_log_file_validation = true

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
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudtrail"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("enable_log_file_validation") {
				set.AddResult().
					WithDescription("Resource '%s' does not enable log file validation.", resourceBlock.FullName())
				return
			}

			logFileValidationAttr := resourceBlock.GetAttribute("enable_log_file_validation")
			if logFileValidationAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not enable log file validation.", resourceBlock.FullName()).
					WithAttribute(logFileValidationAttr)
			}
		},
	})
}
