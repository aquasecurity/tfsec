package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSLaunchConfigurationWithUnencryptedBlockDevice See https://github.com/liamg/tfsec#included-checks for check info
const AWSLaunchConfigurationWithUnencryptedBlockDevice scanner.RuleID = "AWS014"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSLaunchConfigurationWithUnencryptedBlockDevice,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			var encryptionByDefault bool

			for _, defaultEncryptionBlock := range context.GetResourcesByType("aws_ebs_encryption_by_default") {
				enabledAttr := defaultEncryptionBlock.GetAttribute("enabled")
				if enabledAttr == nil || (enabledAttr.Type() == cty.Bool && enabledAttr.Value().True()) {
					encryptionByDefault = true
				}
			}

			var results []scanner.Result

			rootDeviceBlock := block.GetBlock("root_block_device")
			if rootDeviceBlock == nil && !encryptionByDefault {
				results = append(results,
					check.NewResult(
						fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device. Consider adding <blue>root_block_device{ encrypted = true }</blue>", block.Name()),
						block.Range(),
					),
				)
			} else if rootDeviceBlock != nil {
				encryptedAttr := rootDeviceBlock.GetAttribute("encrypted")
				if encryptedAttr == nil && !encryptionByDefault {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device. Consider adding <blue>encrypted = true</blue>", block.Name()),
							rootDeviceBlock.Range(),
						),
					)
				} else if encryptedAttr != nil && encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' uses an unencrypted root EBS block device.", block.Name()),
							encryptedAttr.Range(),
							encryptedAttr,
						),
					)
				}
			}

			ebsDeviceBlocks := block.GetBlocks("ebs_block_device")
			for _, ebsDeviceBlock := range ebsDeviceBlocks {
				encryptedAttr := ebsDeviceBlock.GetAttribute("encrypted")
				if encryptedAttr == nil && !encryptionByDefault {
					results = append(results,
						check.NewResult(
							fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device. Consider adding <blue>encrypted = true</blue>", block.Name()),
							ebsDeviceBlock.Range(),
						),
					)
				} else if encryptedAttr != nil && encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
					results = append(results,
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
							encryptedAttr.Range(),
							encryptedAttr,
						),
					)
				}
			}

			return results
		},
	})
}
