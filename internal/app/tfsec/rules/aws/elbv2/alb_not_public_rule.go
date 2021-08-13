package elbv2

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS005",
		Service:   "elbv2",
		ShortCode: "alb-not-public",
		Documentation: rule.RuleDocumentation{
			Summary: "Load balancer is exposed to the internet.",
			Explanation: `
There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.
`,
			Impact:     "The load balancer is exposed on the internet",
			Resolution: "Switch to an internal load balancer or add a tfsec ignore",
			BadExample: []string{`
resource "aws_alb" "bad_example" {
	internal = false
}
`},
			GoodExample: []string{`
resource "aws_alb" "good_example" {
	internal = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_alb", "aws_elb", "aws_lb"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.HasChild("load_balancer_type") && resourceBlock.GetAttribute("load_balancer_type").Equals("gateway") {
				return
			}
			if internalAttr := resourceBlock.GetAttribute("internal"); internalAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' is exposed publicly.", resourceBlock.FullName())
			} else if internalAttr.Type() == cty.Bool && internalAttr.Value().False() {
				set.AddResult().
					WithDescription("Resource '%s' is exposed publicly.", resourceBlock.FullName()).
					WithAttribute(internalAttr)
			}
		},
	})
}
