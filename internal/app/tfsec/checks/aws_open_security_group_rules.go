package checks

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			typeVal, _, exists := getAttribute(block, ctx, "type")
			if !exists {
				return []models.Result{
					{
						Description: fmt.Sprintf("Resource '%s' is missing the 'type' attribute.", getBlockName(block)),
					},
				}
			}

			if cidrBlocksVal, cidrRange, exists := getAttribute(block, ctx, "cidr_blocks"); exists {

				for _, cidr := range cidrBlocksVal.AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []models.Result{
							{
								Range:       cidrRange,
								Description: fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", getBlockName(block), typeVal.AsString()),
							},
						}
					}
				}

			}

			return nil
		},
	})
}
