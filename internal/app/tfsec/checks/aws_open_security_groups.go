package checks

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// AWSOpenIngressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupInlineRule Code = "AWS008"

// AWSOpenEgressSecurityGroupInlineRule See https://github.com/liamg/tfsec#included-checks for check info
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

				if directionBlock, exists := getBlock(block, direction); exists {
					if cidrBlocksVal, cidrRange, exists := getAttribute(directionBlock, ctx, "cidr_blocks"); exists {
						for _, cidr := range cidrBlocksVal.AsValueSlice() {
							if strings.HasSuffix(cidr.AsString(), "/0") {
								results = append(results,
									NewResult(
										code,
										fmt.Sprintf("Resource '%s' defines a fully open %s security group.", getBlockName(block), direction),
										cidrRange,
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
