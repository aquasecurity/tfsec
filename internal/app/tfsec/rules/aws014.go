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

const AWSLaunchConfigurationWithUnencryptedBlockDevice = "AWS014"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceDescription = "Launch configuration with unencrypted block device."
const AWSLaunchConfigurationWithUnencryptedBlockDeviceImpact = "The block device is could be compromised and read from"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceResolution = "Turn on encryption for all block devices"
const AWSLaunchConfigurationWithUnencryptedBlockDeviceExplanation = `
Blocks devices should be encrypted to ensure sensitive data is held securely at rest.
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
		DefaultSeverity: severity.High,
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
						WithRange(resourceBlock.Range()),
				)
			} else if rootDeviceBlock != nil {
				checkDeviceEncryption(rootDeviceBlock, encryptionByDefault, set, resourceBlock)
			}

			ebsDeviceBlocks := resourceBlock.GetBlocks("ebs_block_device")
			for _, ebsDeviceBlock := range ebsDeviceBlocks {
				checkDeviceEncryption(ebsDeviceBlock, encryptionByDefault, set, resourceBlock)
			}

		},
	})
}

func checkDeviceEncryption(deviceBlock block.Block, encryptionByDefault bool, set result.Set, resourceBlock block.Block) {
	encryptedAttr := deviceBlock.GetAttribute("encrypted")
	if encryptedAttr == nil && !encryptionByDefault {
		set.Add(
			result.New(resourceBlock).
				WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device. Consider adding <blue>encrypted = true</blue>", resourceBlock.FullName())).
				WithRange(deviceBlock.Range()),
		)
	} else if encryptedAttr != nil && encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
		set.Add(
			result.New(resourceBlock).
				WithDescription(fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device.", resourceBlock.FullName())).
				WithRange(encryptedAttr.Range()).
				WithAttributeAnnotation(encryptedAttr),
		)
	}
}
