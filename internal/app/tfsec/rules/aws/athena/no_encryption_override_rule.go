package athena

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
		LegacyID:  "AWS060",
		Service:   "athena",
		ShortCode: "no-encryption-override",
		Documentation: rule.RuleDocumentation{
			Summary:    "Athena workgroups should enforce configuration to prevent client disabling encryption",
			Impact:     "Clients can ignore encryption requirements",
			Resolution: "Enforce the configuration to prevent client overrides",
			Explanation: `
Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.
`,
			BadExample: []string{`
resource "aws_athena_workgroup" "bad_example" {
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

resource "aws_athena_workgroup" "bad_example" {
  name = "example"

}
`},
			GoodExample: []string{`
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#configuration",
				"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_athena_workgroup"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("configuration") {
				set.AddResult().
					WithDescription("Resource '%s' is missing the configuration block.", resourceBlock.FullName())
				return
			}

			configBlock := resourceBlock.GetBlock("configuration")

			configBlock.HasChild("enforce_workgroup_configuration")
			enforceWorkgroupConfigAttr := configBlock.GetAttribute("enforce_workgroup_configuration")

			if enforceWorkgroupConfigAttr.IsNil() {
				return
			}

			if enforceWorkgroupConfigAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has enforce_workgroup_configuration set to false.", resourceBlock.FullName()).
					WithAttribute(enforceWorkgroupConfigAttr)
			}

		},
	})
}
