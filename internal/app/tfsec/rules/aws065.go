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

const AWSCloudtrailEncryptedAtRest = "AWS065"
const AWSCloudtrailEncryptedAtRestDescription = "Cloudtrail should be encrypted at rest to secure access to sensitive trail data"
const AWSCloudtrailEncryptedAtRestImpact = "Data can be freely read if compromised"
const AWSCloudtrailEncryptedAtRestResolution = "Enable encryption at rest"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudtrailEncryptedAtRest,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSCloudtrailEncryptedAtRestDescription,
			Impact:      AWSCloudtrailEncryptedAtRestImpact,
			Resolution:  AWSCloudtrailEncryptedAtRestResolution,
			Explanation: AWSCloudtrailEncryptedAtRestExplanation,
			BadExample:  AWSCloudtrailEncryptedAtRestBadExample,
			GoodExample: AWSCloudtrailEncryptedAtRestGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudtrail"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("kms_key_id") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have a kms_key_id set.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			kmsKeyIdAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyIdAttr.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has a kms_key_id but it is not set.", resourceBlock.FullName())).
						WithRange(kmsKeyIdAttr.Range()).
						WithAttributeAnnotation(kmsKeyIdAttr),
				)
			}

		},
	})
}
