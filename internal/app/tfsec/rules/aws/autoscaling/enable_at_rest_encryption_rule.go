package autoscaling

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
		LegacyID:  "AWS014",
		Service:   "autoscaling",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			Summary:    "Launch configuration with unencrypted block device.",
			Impact:     "The block device could be compromised and read from",
			Resolution: "Turn on encryption for all block devices",
			Explanation: `
Blocks devices should be encrypted to ensure sensitive data is held securely at rest.
`,
			BadExample: []string{`
resource "aws_launch_configuration" "bad_example" {
	root_block_device {
		encrypted = false
	}
}
`},
			GoodExample: []string{`
resource "aws_launch_configuration" "good_example" {
	root_block_device {
		encrypted = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_launch_configuration"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			var encryptionByDefault bool

			for _, defaultEncryptionBlock := range context.GetResourcesByType("aws_ebs_encryption_by_default") {
				enabledAttr := defaultEncryptionBlock.GetAttribute("enabled")
				if enabledAttr.IsTrue() {
					encryptionByDefault = true
				}
			}

			rootDeviceBlock := resourceBlock.GetBlock("root_block_device")
			if rootDeviceBlock.IsNil() && !encryptionByDefault {
				set.AddResult().
					WithDescription("Resource '%s' uses an unencrypted root EBS block device. Consider adding <blue>root_block_device{ encrypted = true }</blue>", resourceBlock.FullName())
			} else if rootDeviceBlock.IsNotNil() {
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
	if encryptedAttr.IsNil() && !encryptionByDefault {
		set.AddResult().
			WithDescription("Resource '%s' uses an unencrypted EBS block device. Consider adding <blue>encrypted = true</blue>", resourceBlock.FullName())
	} else if encryptedAttr.IsFalse() {
		set.AddResult().
			WithDescription("Resource '%s' uses an unencrypted root EBS block device.", resourceBlock.FullName()).
			WithAttribute(encryptedAttr)
	}
}
