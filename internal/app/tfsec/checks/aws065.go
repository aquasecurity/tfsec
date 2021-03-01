package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudtrailEncryptedAtRest scanner.RuleCode = "AWS065"
const AWSCloudtrailEncryptedAtRestDescription scanner.RuleSummary = "Cloudtrail should be encrypted at rest to secure access to sensitive trail data"
const AWSCloudtrailEncryptedAtRestExplanation = `
Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.
`
const AWSCloudtrailEncryptedAtRestBadExample = `
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
const AWSCloudtrailEncryptedAtRestGoodExample = `
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = var.kms_id

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
		Code: AWSCloudtrailEncryptedAtRest,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudtrailEncryptedAtRestDescription,
			Explanation: AWSCloudtrailEncryptedAtRestExplanation,
			BadExample:  AWSCloudtrailEncryptedAtRestBadExample,
			GoodExample: AWSCloudtrailEncryptedAtRestGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudtrail"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
				
			if block.MissingChild("kms_key_id") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a kms_key_id set.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
						),
				}
			}

			kmsKeyId := block.GetAttribute("kms_key_id")
			if kmsKeyId.IsEmpty() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has a kms_key_id but it is not set.", block.FullName()),
						kmsKeyId.Range(),
						kmsKeyId,
						scanner.SeverityError,
						),
				}
			}

			return nil
		},
	})
}
