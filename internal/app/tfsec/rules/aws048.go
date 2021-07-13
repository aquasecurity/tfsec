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
	"github.com/zclconf/go-cty/cty"
)

const AWSEfsEncryptionNotEnabled = "AWS048"
const AWSEfsEncryptionNotEnabledDescription = "EFS Encryption has not been enabled"
const AWSEfsEncryptionNotEnabledImpact = "Data can be read from the EFS if compromised"
const AWSEfsEncryptionNotEnabledResolution = "Enable encryption for EFS"
const AWSEfsEncryptionNotEnabledExplanation = `
If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

`
const AWSEfsEncryptionNotEnabledBadExample = `
resource "aws_efs_file_system" "bad_example" {
  name       = "bar"
  encrypted  = false
  kms_key_id = ""
}`
const AWSEfsEncryptionNotEnabledGoodExample = `
resource "aws_efs_file_system" "good_example" {
  name       = "bar"
  encrypted  = true
  kms_key_id = "my_kms_key"
}`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSEfsEncryptionNotEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSEfsEncryptionNotEnabledDescription,
			Impact:      AWSEfsEncryptionNotEnabledImpact,
			Resolution:  AWSEfsEncryptionNotEnabledResolution,
			Explanation: AWSEfsEncryptionNotEnabledExplanation,
			BadExample:  AWSEfsEncryptionNotEnabledBadExample,
			GoodExample: AWSEfsEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_efs_file_system"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			efsEnabledAttr := resourceBlock.GetAttribute("encrypted")

			if efsEnabledAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not specify if encryption should be used.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if efsEnabledAttr.Type() == cty.Bool && efsEnabledAttr.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' actively does not have encryption applied.", resourceBlock.FullName())).
						WithRange(efsEnabledAttr.Range()).
						WithAttributeAnnotation(efsEnabledAttr),
				)
			}
		},
	})
}
