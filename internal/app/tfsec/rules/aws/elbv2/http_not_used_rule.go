package elbv2

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS004",
		Service:   "elbv2",
		ShortCode: "http-not-used",
		Documentation: rule.RuleDocumentation{
			Summary: "Use of plain HTTP.",
			Explanation: `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`,
			Impact:     "Your traffic is not protected",
			Resolution: "Switch to HTTPS to benefit from TLS security features",
			BadExample: []string{`
resource "aws_alb_listener" "bad_example" {
	protocol = "HTTP"
}
`},
			GoodExample: []string{`
resource "aws_alb_listener" "good_example" {
	protocol = "HTTPS"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
				"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lb_listener", "aws_alb_listener"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			// didn't find the referenced block, log and move on
			if checkIfExempt(resourceBlock, module) {
				return
			}

			protocolAttr := resourceBlock.GetAttribute("protocol")

			if protocolAttr.IsNotNil() {
				if protocolAttr.IsResolvable() && (protocolAttr.Equals("HTTPS", block.IgnoreCase) ||
					protocolAttr.Equals("TLS", block.IgnoreCase)) {
					return
				}
				if protocolAttr.IsResolvable() && protocolAttr.Equals("HTTP") {
					// check if this is a redirect to HTTPS - if it is, then no problem
					if redirectProtocolAttr := resourceBlock.GetNestedAttribute("default_action.redirect.protocol"); redirectProtocolAttr.IsNotNil() {
						if redirectProtocolAttr.IsResolvable() && redirectProtocolAttr.Equals("HTTPS") {
							return
						}
					}
				}
			}

			set.AddResult().
				WithDescription("Resource '%s' uses plain HTTP instead of HTTPS.", resourceBlock.FullName()).
				WithAttribute(protocolAttr)

		},
	})
}

func checkIfExempt(resourceBlock block.Block, module block.Module) bool {
	if resourceBlock.HasChild("load_balancer_arn") {
		lbaAttr := resourceBlock.GetAttribute("load_balancer_arn")
		if lbaAttr.IsResourceBlockReference("aws_lb") {
			referencedBlock, err := module.GetReferencedBlock(lbaAttr)
			if err == nil {
				if referencedBlock.HasChild("load_balancer_type") {
					loadBalancerType := referencedBlock.GetAttribute("load_balancer_type")
					if loadBalancerType.IsAny("gateway", "network") {
						return true
					}
				}
			} else {

				debug.Log(err.Error())
			}
		}
	}
	return false
}
