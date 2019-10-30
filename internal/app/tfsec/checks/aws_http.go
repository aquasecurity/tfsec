package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			if val, attrRange, exists := getAttribute(block, ctx, "protocol"); !exists || val.AsString() == "HTTP" {
				return []models.Result{
					{
						Range:       attrRange,
						Description: fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", getBlockName(block)),
					},
				}
			}

			return nil
		},
	})
}
