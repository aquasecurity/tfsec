package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			val, attrRange, exists := getAttribute(block, ctx, "ebs_block_device")
			if !exists {
				return []models.Result{
					{
						Description: fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
					},
				}
			}

			values := val.AsValueMap()
			encrypted, exists := values["encrypted"]
			if !exists {
				return []models.Result{
					{
						Description: fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
					},
				}
			}

			if encrypted.False() {
				return []models.Result{
					{
						Range:       attrRange,
						Description: fmt.Sprintf("Resource '%s' uses an unencrypted EBS block device.", getBlockName(block)),
					},
				}
			}

			return nil
		},
	})
}
