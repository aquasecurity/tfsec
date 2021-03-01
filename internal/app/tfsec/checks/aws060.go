package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSAthenaWorkgroupEnforceConfiguration scanner.RuleCode = "AWS060"
const AWSAthenaWorkgroupEnforceConfigurationDescription scanner.RuleSummary = "Athena workgroups should enforce configuration to prevent client disabling encryption"
const AWSAthenaWorkgroupEnforceConfigurationExplanation = `
Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.
`
const AWSAthenaWorkgroupEnforceConfigurationBadExample = `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = false
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}

resource "aws_athena_workgroup" "good_example" {
  name = "example"

}
`
const AWSAthenaWorkgroupEnforceConfigurationGoodExample = `
resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSAthenaWorkgroupEnforceConfiguration,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSAthenaWorkgroupEnforceConfigurationDescription,
			Explanation: AWSAthenaWorkgroupEnforceConfigurationExplanation,
			BadExample:  AWSAthenaWorkgroupEnforceConfigurationBadExample,
			GoodExample: AWSAthenaWorkgroupEnforceConfigurationGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration",
				"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_athena_workgroup"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("configuration") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is missing the configuration block.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			configBlock := block.GetBlock("configuration")
			if configBlock.HasChild("enforce_workgroup_configuration") &&
				configBlock.GetAttribute("enforce_workgroup_configuration").IsFalse() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has enforce_workgroup_configuration set to false.", block.FullName()),
						configBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
