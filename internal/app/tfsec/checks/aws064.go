package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudtrailLogValidationEnabled scanner.RuleCode = "AWS064"
const AWSCloudtrailLogValidationEnabledDescription scanner.RuleSummary = "Cloudtrail log validation should be enabled to prevent tampering of log data"
const AWSCloudtrailLogValidationEnabledExplanation = `
Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.
`
const AWSCloudtrailLogValidationEnabledBadExample = `
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
`
const AWSCloudtrailLogValidationEnabledGoodExample = `
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
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudtrailLogValidationEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudtrailLogValidationEnabledDescription,
			Explanation: AWSCloudtrailLogValidationEnabledExplanation,
			BadExample:  AWSCloudtrailLogValidationEnabledBadExample,
			GoodExample: AWSCloudtrailLogValidationEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_log_file_validation",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudtrail"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if block.MissingChild("enable_log_file_validation")  {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not enable log file validation.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			}

			logFileValidation := block.GetAttribute("enable_log_file_validation")
			if logFileValidation.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' does not enable log file validation.", block.FullName()),
						logFileValidation.Range(),
						logFileValidation,
						scanner.SeverityWarning,
					),
				}
			}/**/
			return nil
		},
	})
}
