package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			if val, attrRange, exists := getAttribute(block, ctx, "associate_public_ip_address"); exists {
				if val.True() {
					return []models.Result{
						{
							Range:       attrRange,
							Description: fmt.Sprintf("Resource '%s' has a public IP address associated.", getBlockName(block)),
						},
					}
				}
			}

			return nil
		},
	})
}
