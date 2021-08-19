package s3

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/defsec/rules/aws/s3"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS017",
		Service:   "s3",
		ShortCode: "enable-bucket-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Unencrypted S3 bucket.",
			Impact:     "The bucket objects could be read if compromised",
			Resolution: "Configure bucket encryption",
			Explanation: `
S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.
`,
			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "arn"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
			},
		},
		Provider:            provider.AWSProvider,
		RequiredTypes:       []string{"resource"},
		RequiredLabels:      []string{"aws_s3_bucket"},
		DefaultSeverity:     severity.High,
		CheckInfrastructure: s3.CheckEncryptionIsEnabled,
	})
}
