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
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) *models.Result {
			for _, direction := range []string{"ingress", "egress"} {
				if directionVal, directionRange, exists := getAttribute(block, ctx, direction); exists {
					directionMap := directionVal.AsValueMap()
					if cidrBlocksVal, exists := directionMap["cidr_blocks"]; exists {
						for _, cidr := range cidrBlocksVal.AsValueSlice() {
							if strings.HasSuffix(cidr.AsString(), "/0") {
								return &models.Result{
									Range:       directionRange,
									Description: fmt.Sprintf("Resource '%s' defines a fully open %s security group.", getBlockName(block), direction),
								}
							}
						}
					}
				}
			}

			return nil
		},
	})
}
