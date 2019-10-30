package checks

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

const AWSOpenIngressSecurityGroupInlineRule Code = "AWS008"
const AWSOpenEgressSecurityGroupInlineRule Code = "AWS009"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			var results []Result

			for _, direction := range []string{"ingress", "egress"} {

				code := AWSOpenIngressSecurityGroupInlineRule
				if direction == "egress" {
					code = AWSOpenEgressSecurityGroupInlineRule
				}

				if directionVal, directionRange, exists := getAttribute(block, ctx, direction); exists {
					directionMap := directionVal.AsValueMap()
					if cidrBlocksVal, exists := directionMap["cidr_blocks"]; exists {
						for _, cidr := range cidrBlocksVal.AsValueSlice() {
							if strings.HasSuffix(cidr.AsString(), "/0") {
								results = append(results,
									NewResult(
										code,
										fmt.Sprintf("Resource '%s' defines a fully open %s security group.", getBlockName(block), direction),
										directionRange,
									),
								)
							}
						}
					}
				}
			}

			return results
		},
	})
}
