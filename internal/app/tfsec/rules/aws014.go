package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

const AWSLaunchConfigurationWithUnencryptedBlockDevice = "AWS014"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceDescription = "Launch configuration with unencrypted block device."
const AWSLaunchConfigurationWithUnencryptedBlockDeviceImpact = "The block device is could be compromised and read from"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceResolution = "Turn on encryption for all block devices"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceExplanation = `
Blocks devices should be encrypted to ensure sensitive data is hel securely at rest.
`
const AWSLaunchConfigurationWithUnencryptedBlockDeviceBadExample = `
resource "aws_launch_configuration" "bad_example" {
	root_block_device {
		encrypted = false
	}
}
`
const AWSLaunchConfigurationWithUnencryptedBlockDeviceGoodExample = `
resource "aws_launch_configuration" "good_example" {
	root_block_device {
		encrypted = true
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSLaunchConfigurationWithUnencryptedBlockDevice,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSLaunchConfigurationWithUnencryptedBlockDeviceDescription,
			Impact:      AWSLaunchConfigurationWithUnencryptedBlockDeviceImpact,
			Resolution:  AWSLaunchConfigurationWithUnencryptedBlockDeviceResolution,
			Explanation: AWSLaunchConfigurationWithUnencryptedBlockDeviceExplanation,
			BadExample:  AWSLaunchConfigurationWithUnencryptedBlockDeviceBadExample,
			GoodExample: AWSLaunchConfigurationWithUnencryptedBlockDeviceGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_launch_configuration"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			var encryptionByDefault bool

			for _, defaultEncryptionBlock := range context.GetResourcesByType("aws_ebs_encryption_by_default") {
				enabledAttr := defaultEncryptionBlock.GetAttribute("enabled")
				if enabledAttr == nil || (enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()) {
					encryptionByDefault = true
				}
			}

			rootDeviceBlock := resourceBlock.GetBlock("root_block_device")
			if rootDeviceBlock == nil && !encryptionByDefault {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device. Consider adding <blue>root_block_device{ encrypted = true }</blue>", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()).
						WithSeverity(severity.Error),
				)
			} else if rootDeviceBlock != nil {
				encryptedAttr := rootDeviceBlock.GetAttribute("encrypted")
				if encryptedAttr == nil && !encryptionByDefault {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device. Consider adding <blue>encrypted = true</blue>", resourceBlock.FullName())).
							WithRange(rootDeviceBlock.Range()).
							WithSeverity(severity.Error),
					)
				} else if encryptedAttr != nil && encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device.", resourceBlock.FullName())).
							WithRange(encryptedAttr.Range()).
							WithAttributeAnnotation(encryptedAttr).
							WithSeverity(severity.Error),
					)
				}
			}

			ebsDeviceBlocks := resourceBlock.GetBlocks("ebs_block_device")
			for _, ebsDeviceBlock := range ebsDeviceBlocks {
				encryptedAttr := ebsDeviceBlock.GetAttribute("encrypted")
				if encryptedAttr == nil && !encryptionByDefault {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device. Consider adding <blue>encrypted = true</blue>", resourceBlock.FullName())).
							WithRange(ebsDeviceBlock.Range()).
							WithSeverity(severity.Error),
					)
				} else if encryptedAttr != nil && encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", resourceBlock.FullName())).
							WithRange(encryptedAttr.Range()).
							WithAttributeAnnotation(encryptedAttr).
							WithSeverity(severity.Error),
					)
				}
			}

		},
	})
}
