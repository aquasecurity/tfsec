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
		LegacyID:  "AWS065",
		Service:   "cloudtrail",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Cloudtrail should be encrypted at rest to secure access to sensitive trail data",
			Impact:     "Data can be freely read if compromised",
			Resolution: "Enable encryption at rest",
			Explanation: `
Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id",
				"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudtrail"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("kms_key_id") {
				set.AddResult().
					WithDescription("Resource '%s' does not have a kms_key_id set.", resourceBlock.FullName())
				return
			}

			kmsKeyIdAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyIdAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' has a kms_key_id but it is not set.", resourceBlock.FullName()).
					WithAttribute(kmsKeyIdAttr)
			}

		},
	})
}
