package autoscaling

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS014",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		Base:           autoscaling.CheckEnableAtRestEncryption,
		CheckTerraform: func(resourceBlock block.Block, module block.Module) (results rules.Results) {

			var encryptionByDefault bool
			for _, defaultEncryptionBlock := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
				enabledAttr := defaultEncryptionBlock.GetAttribute("enabled")
				if enabledAttr.IsTrue() {
					encryptionByDefault = true
				}
			}

			rootDeviceBlock := resourceBlock.GetBlock("root_block_device")
			if rootDeviceBlock.IsNil() && !encryptionByDefault {
				results.Add("Resource uses an unencrypted root EBS block device. Consider adding 'root_block_device{ encrypted = true }'", resourceBlock)
			} else if rootDeviceBlock.IsNotNil() {
				results = append(results, checkDeviceEncryption(rootDeviceBlock, encryptionByDefault, resourceBlock)...)
			}

			ebsDeviceBlocks := resourceBlock.GetBlocks("ebs_block_device")
			for _, ebsDeviceBlock := range ebsDeviceBlocks {
				results = append(results, checkDeviceEncryption(ebsDeviceBlock, encryptionByDefault, resourceBlock)...)
			}

			return results
		},
	})
}

func checkDeviceEncryption(deviceBlock block.Block, encryptionByDefault bool, resourceBlock block.Block) (results rules.Results) {
	encryptedAttr := deviceBlock.GetAttribute("encrypted")
	if encryptedAttr.IsNil() && !encryptionByDefault {
		results.Add("Resource uses an unencrypted EBS block device. Consider adding 'encrypted = true'", deviceBlock)
	} else if encryptedAttr.IsFalse() {
		results.Add("Resource uses an unencrypted root EBS block device.", encryptedAttr)
	}
	return results
}
