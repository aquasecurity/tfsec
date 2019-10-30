package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
)

// AWSPlainHTTP See https://github.com/liamg/tfsec#included-checks for check info
const AWSPlainHTTP Code = "AWS004"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {
			if val, attrRange, exists := getAttribute(block, ctx, "protocol"); !exists || val.AsString() == "HTTP" {
				// check if this is a redirect to HTTPS - if it is, then no problem
				if actionBlock, exists := getBlock(block, "default_action"); exists {
					if actionType, _, exists := getAttribute(actionBlock, ctx, "type"); exists && actionType.Type() == cty.String && actionType.AsString() == "redirect" {
						if redirectBlock, exists := getBlock(actionBlock, "redirect"); exists {
							if protocol, _, ok := getAttribute(redirectBlock, ctx, "protocol"); ok && protocol.Type() == cty.String && protocol.AsString() == "HTTPS" {
								return nil
							}
						}
					}
				}
				return []Result{
					NewResult(
						AWSPlainHTTP,
						fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", getBlockName(block)),
						attrRange,
					),
				}
			}
			return nil
		},
	})
}
