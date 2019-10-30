package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_s3_bucket"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {
			if _, _, exists := getAttribute(block, ctx, "logging"); !exists {
				return []models.Result{
					{
						Description: fmt.Sprintf("Resource '%s' does not have logging enabled.", getBlockName(block)),
					},
				}
			}
			return nil
		},
	})
}
