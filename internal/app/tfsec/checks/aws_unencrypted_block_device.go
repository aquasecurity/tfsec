package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSLaunchConfigurationWithUnencryptedBlockDevice See https://github.com/liamg/tfsec#included-checks for check info
const AWSLaunchConfigurationWithUnencryptedBlockDevice Code = "AWS014"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		CheckFunc: func(block *parser.Block) []Result {

			deviceBlock := block.GetBlock("ebs_block_device")
			if deviceBlock == nil {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						block.Range(),
					),
				}
			}

			encryptedAttr := deviceBlock.GetAttribute("encrypted")
			if encryptedAttr == nil {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						deviceBlock.Range(),
					),
				}
			}

			if encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						encryptedAttr.Range(),
					),
				}
			}

			return nil
		},
	})
}
