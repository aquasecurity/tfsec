package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSExternallyExposedLoadBalancer scanner.RuleCode = "AWS005"
const AWSExternallyExposedLoadBalancerDescription scanner.RuleSummary = "Load balancer is exposed to the internet."
const AWSExternallyExposedLoadBalancerExplanation = `
There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.
`
const AWSExternallyExposedLoadBalancerBadExample = `
resource "aws_alb" "my-resource" {
	internal = false
}
`
const AWSExternallyExposedLoadBalancerGoodExample = `
resource "aws_alb" "my-resource" {
	internal = true
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSExternallyExposedLoadBalancer,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSExternallyExposedLoadBalancerDescription,
			Explanation: AWSExternallyExposedLoadBalancerExplanation,
			BadExample:  AWSExternallyExposedLoadBalancerBadExample,
			GoodExample: AWSExternallyExposedLoadBalancerGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_alb", "aws_elb", "aws_lb"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if internalAttr := block.GetAttribute("internal"); internalAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' is exposed publicly.", block.FullName()),
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
