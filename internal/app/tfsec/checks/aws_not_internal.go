package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/liamg/tfsec/internal/app/tfsec/parser"
)

// AWSExternallyExposedLoadBalancer See https://github.com/liamg/tfsec#included-checks for check info
const AWSExternallyExposedLoadBalancer Code = "AWS005"

func init() {
	RegisterCheck(Check{
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		CheckFunc: func(block *parser.Block) []Result {
			if internalAttr := block.GetAttribute("internal"); internalAttr == nil {
				return []Result{
					NewResult(
						AWSExternallyExposedLoadBalancer,
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.Name()),
						block.Range(),
					),
				}
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				return []Result{
					NewResult(
						AWSExternallyExposedLoadBalancer,
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.Name()),
						internalAttr.Range(),
					),
				}
			}
			return nil
		},
	})
}
