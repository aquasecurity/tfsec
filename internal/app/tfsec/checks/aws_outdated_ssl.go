package checks

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/liamg/tfsec/internal/app/tfsec/models"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(block *hcl.Block, ctx *hcl.EvalContext) []models.Result {

			if val, attrRange, exists := getAttribute(block, ctx, "ssl_policy"); exists {
				for _, policy := range outdatedSSLPolicies {
					if policy == val.AsString() {
						return []models.Result{
							{
								Range:       attrRange,
								Description: fmt.Sprintf("Resource '%s' is using an outdated SSL policy.", getBlockName(block)),
							},
						}
					}
				}
			}

			return nil
		},
	})
}
