package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSLaunchConfigurationWithUnencryptedBlockDevice Code = "AWS014"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			val, attrRange, exists := getAttribute(block, ctx, "ebs_block_device")
			if !exists {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
						nil,
					),
				}
			}

			values := val.AsValueMap()
			encrypted, exists := values["encrypted"]
			if !exists {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
						nil,
					),
				}
			}

			if encrypted.False() {
				return []Result{
					NewResult(
						AWSLaunchConfigurationWithUnencryptedBlockDevice,
						fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
						attrRange,
					),
				}
			}

			return nil
		},
	})
}
