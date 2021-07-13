package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSPlainHTTP = "AWS004"
const AWSPlainHTTPDescription = "Use of plain HTTP."
const AWSPlainHTTPImpact = "Your traffic is not protected"
const AWSPlainHTTPResolution = "Switch to HTTPS to benefit from TLS security features"
const AWSPlainHTTPExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const AWSPlainHTTPBadExample = `
resource "aws_alb_listener" "bad_example" {
	protocol = "HTTP"
}
`
const AWSPlainHTTPGoodExample = `
resource "aws_alb_listener" "good_example" {
	protocol = "HTTPS"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSPlainHTTP,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSPlainHTTPDescription,
			Explanation: AWSPlainHTTPExplanation,
			Impact:      AWSPlainHTTPImpact,
			Resolution:  AWSPlainHTTPResolution,
			BadExample:  AWSPlainHTTPBadExample,
			GoodExample: AWSPlainHTTPGoodExample,
			Links: []string{
				"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lb_listener", "aws_alb_listener"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, ctx *hclcontext.Context) {
			// didn't find the referenced block, log and move on
			if checkIfExempt(resourceBlock, ctx) {
				return
			}

			protocolAttr := resourceBlock.GetAttribute("protocol")

			if protocolAttr != nil {
				if protocolAttr.IsResolvable() && (protocolAttr.Equals("HTTPS", block.IgnoreCase) ||
					protocolAttr.Equals("TLS", block.IgnoreCase)) {
					return
				}
				if protocolAttr.IsResolvable() && protocolAttr.Equals("HTTP") {
					// check if this is a redirect to HTTPS - if it is, then no problem
					if redirectProtocolAttr := resourceBlock.GetNestedAttribute("default_action/redirect/protocol"); redirectProtocolAttr != nil {
						if redirectProtocolAttr.IsResolvable() && redirectProtocolAttr.Equals("HTTPS") {
							return
						}
					}
				}
			}

			res := result.New(resourceBlock).
				WithDescription(fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", resourceBlock.FullName())).
				WithRange(resourceBlock.Range())

			if protocolAttr != nil {
				res.WithRange(protocolAttr.Range()).
					WithAttributeAnnotation(protocolAttr)
			}

			set.Add(res)

		},
	})
}

func checkIfExempt(resourceBlock block.Block, ctx *hclcontext.Context) bool {
	if resourceBlock.HasChild("load_balancer_arn") {
		lbaAttr := resourceBlock.GetAttribute("load_balancer_arn")
		if lbaAttr.IsResourceBlockReference("aws_lb") {
			referencedBlock, err := ctx.GetReferencedBlock(lbaAttr)
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
