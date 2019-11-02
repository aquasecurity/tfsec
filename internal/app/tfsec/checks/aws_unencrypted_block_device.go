package checks

import (
	"fmt"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSLaunchConfigurationWithUnencryptedBlockDevice See https://github.com/liamg/tfsec#included-checks for check info
const AWSLaunchConfigurationWithUnencryptedBlockDevice scanner.Code = "AWS014"

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSLaunchConfigurationWithUnencryptedBlockDevice,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		CheckFunc: func(check *scanner.Check, block *parser.Block) []scanner.Result {

			deviceBlock := block.GetBlock("ebs_block_device")
			if deviceBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						block.Range(),
					),
				}
			}

			encryptedAttr := deviceBlock.GetAttribute("encrypted")
			if encryptedAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						deviceBlock.Range(),
					),
				}
			}

			if encryptedAttr.Type() == cty.Bool && encryptedAttr.Value().False() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", block.Name()),
						encryptedAttr.Range(),
					),
				}
			}

			return nil
		},
	})
}
