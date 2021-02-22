package checks

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEnsureAthenaDbEncrypted scanner.RuleCode = "AWS059"
const AWSEnsureAthenaDbEncryptedDescription scanner.RuleSummary = "Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted"
const AWSEnsureAthenaDbEncryptedExplanation = `
Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.

`
const AWSEnsureAthenaDbEncryptedBadExample = `
resource "aws_athena_database" "bad_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket
}

resource "aws_athena_workgroup" "bad_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
    }
  }
}
`
const AWSEnsureAthenaDbEncryptedGoodExample = `
resource "aws_athena_database" "good_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket

  encryption_configuration {
     encryption_option = "SSE_KMS"
     kms_key_arn       = aws_kms_key.example.arn
 }
}

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
		Code: AWSEnsureAthenaDbEncrypted,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEnsureAthenaDbEncryptedDescription,
			Explanation: AWSEnsureAthenaDbEncryptedExplanation,
			BadExample:  AWSEnsureAthenaDbEncryptedBadExample,
			GoodExample: AWSEnsureAthenaDbEncryptedGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration",
				"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_athena_database", "aws_athena_workgroup"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			blockName := block.FullName()

			if strings.EqualFold(block.TypeLabel(), "aws_athena_workgroup") {
				if block.HasChild("configuration") && block.GetBlock("configuration").
					HasChild("result_configuration") {
					block = block.GetBlock("configuration").GetBlock("result_configuration")
				} else {
					return nil
				}
			}

			if block.MissingChild("encryption_configuration") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' missing encryption configuration block.", blockName),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
