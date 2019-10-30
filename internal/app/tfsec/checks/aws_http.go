package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSPlainHTTP Code = "AWS004"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {
			if val, attrRange, exists := getAttribute(block, ctx, "protocol"); !exists || val.AsString() == "HTTP" {
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
