package checks

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// AWSOpenIngressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenIngressSecurityGroupRule Code = "AWS006"

// AWSOpenEgressSecurityGroupRule See https://github.com/liamg/tfsec#included-checks for check info
const AWSOpenEgressSecurityGroupRule Code = "AWS007"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {

			typeVal, _, exists := getAttribute(block, ctx, "type")
			if !exists {
				return nil
			}

			code := AWSOpenIngressSecurityGroupRule
			if typeVal.AsString() == "egress" {
				code = AWSOpenEgressSecurityGroupRule
			}

			if cidrBlocksVal, cidrRange, exists := getAttribute(block, ctx, "cidr_blocks"); exists {

				for _, cidr := range cidrBlocksVal.AsValueSlice() {
					if strings.HasSuffix(cidr.AsString(), "/0") {
						return []Result{
							NewResult(
								code,
								fmt.Sprintf("Resource '%s' defines a fully open %s security group rule.", getBlockName(block), typeVal.AsString()),
								cidrRange,
							),
						}
					}
				}

			}

			return nil
		},
	})
}
