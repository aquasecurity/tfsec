package efs

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
		LegacyID:  "AWS048",
		Service:   "efs",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "EFS Encryption has not been enabled",
			Impact:     "Data can be read from the EFS if compromised",
			Resolution: "Enable encryption for EFS",
			Explanation: `
If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

`,
			BadExample: []string{`
resource "aws_efs_file_system" "bad_example" {
  name       = "bar"
  encrypted  = false
  kms_key_id = ""
}`},
			GoodExample: []string{`
resource "aws_efs_file_system" "good_example" {
  name       = "bar"
  encrypted  = true
  kms_key_id = "my_kms_key"
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system",
				"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_efs_file_system"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			efsEnabledAttr := resourceBlock.GetAttribute("encrypted")

			if efsEnabledAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' does not specify if encryption should be used.", resourceBlock.FullName())
				return
			}
			if efsEnabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' actively does not have encryption applied.", resourceBlock.FullName()).
					WithAttribute(efsEnabledAttr)
			}
		},
	})
}
