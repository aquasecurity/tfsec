package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSResourceHasPublicIP Code = "AWS012"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			if val, attrRange, exists := getAttribute(block, ctx, "associate_public_ip_address"); exists {
				if val.True() {
					return []Result{
						NewResult(
							AWSResourceHasPublicIP,
							fmt.Sprintf("Resource '%s' has a public IP address associated.", getBlockName(block)),
							attrRange,
						),
					}
				}
			}

			return nil
		},
	})
}
