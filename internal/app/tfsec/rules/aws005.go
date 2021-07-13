package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

const AWSExternallyExposedLoadBalancer = "AWS005"
const AWSExternallyExposedLoadBalancerDescription = "Load balancer is exposed to the internet."
const AWSExternallyExposedLoadBalancerImpact = "The load balancer is exposed on the internet"
const AWSExternallyExposedLoadBalancerResolution = "Switch to an internal load balancer or add a tfsec ignore"
const AWSExternallyExposedLoadBalancerExplanation = `
There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.
`
const AWSExternallyExposedLoadBalancerBadExample = `
resource "aws_alb" "bad_example" {
	internal = false
}
`
const AWSExternallyExposedLoadBalancerGoodExample = `
resource "aws_alb" "good_example" {
	internal = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSExternallyExposedLoadBalancer,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSExternallyExposedLoadBalancerDescription,
			Explanation: AWSExternallyExposedLoadBalancerExplanation,
			Impact:      AWSExternallyExposedLoadBalancerImpact,
			Resolution:  AWSExternallyExposedLoadBalancerResolution,
			BadExample:  AWSExternallyExposedLoadBalancerBadExample,
			GoodExample: AWSExternallyExposedLoadBalancerGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_alb", "aws_elb", "aws_lb"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.HasChild("load_balancer_type") && resourceBlock.GetAttribute("load_balancer_type").Equals("gateway") {
				return
			}
			if internalAttr := resourceBlock.GetAttribute("internal"); internalAttr == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is exposed publicly.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' is exposed publicly.", resourceBlock.FullName())).
						WithRange(internalAttr.Range()).
						WithAttributeAnnotation(internalAttr),
				)
			}
		},
	})
}
