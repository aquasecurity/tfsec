package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

const AWSExternallyExposedLoadBalancer Code = "AWS005"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []Result {
			if val, attrRange, exists := getAttribute(block, ctx, "internal"); !exists {
				return []Result{
					NewResult(
						AWSExternallyExposedLoadBalancer,
						fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
						nil,
					),
				}
			} else if val.False() {
				return []Result{
					NewResult(
						AWSExternallyExposedLoadBalancer,
						fmt.Sprintf("Resource '%s' is exposed publicly.", getBlockName(block)),
						attrRange,
					),
				}
			}
			return nil
		},
	})
}
