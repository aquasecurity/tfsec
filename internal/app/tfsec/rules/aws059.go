package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSEnsureAthenaDbEncrypted = "AWS059"
const AWSEnsureAthenaDbEncryptedDescription = "Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted"
const AWSEnsureAthenaDbEncryptedImpact = "Data can be read if the Athena Database is compromised"
const AWSEnsureAthenaDbEncryptedResolution = "Enable encryption at rest for Athena databases and workgroup configurations"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSEnsureAthenaDbEncrypted,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSEnsureAthenaDbEncryptedDescription,
			Impact:      AWSEnsureAthenaDbEncryptedImpact,
			Resolution:  AWSEnsureAthenaDbEncryptedResolution,
			Explanation: AWSEnsureAthenaDbEncryptedExplanation,
			BadExample:  AWSEnsureAthenaDbEncryptedBadExample,
			GoodExample: AWSEnsureAthenaDbEncryptedGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration",
				"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_athena_database", "aws_athena_workgroup"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			blockName := resourceBlock.FullName()

			if strings.EqualFold(resourceBlock.TypeLabel(), "aws_athena_workgroup") {
				if !resourceBlock.HasChild("configuration") {
					return
				}
				configBlock := resourceBlock.GetBlock("configuration")
				if !configBlock.HasChild("result_configuration") {
					return
				}
				resourceBlock = configBlock.GetBlock("result_configuration")
			}

			if resourceBlock.MissingChild("encryption_configuration") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' missing encryption configuration block.", blockName)).
						WithRange(resourceBlock.Range()),
				)
			}

		},
	})
}
