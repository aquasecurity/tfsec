package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSExternallyExposedLoadBalancer See https://github.com/tfsec/tfsec#included-checks for check info
const AWSExternallyExposedLoadBalancer scanner.RuleID = "AWS005"
const AWSExternallyExposedLoadBalancerDescription scanner.RuleDescription = "Load balancer is exposed to the internet."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSExternallyExposedLoadBalancer,
		Description:    AWSExternallyExposedLoadBalancerDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if internalAttr := block.GetAttribute("internal"); internalAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.Name()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.Name()),
						internalAttr.Range(),
						internalAttr,
						scanner.SeverityWarning,
					),
				}
			}
			return nil
		},
	})
}
