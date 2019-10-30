package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {
			if val, attrRange, exists := getAttribute(block, ctx, "internal"); !exists {
				return []models.Result{
					{
						Description: fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
					},
				}
			} else if val.False() {
				return []models.Result{
					{
						Range:       attrRange,
						Description: fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
					},
				}
			}
			return nil
		},
	})
}
