package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
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
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock *block.Block, ctx *hclcontext.Context) {
			if resourceBlock.HasChild("load_balancer_arn") {
				lbaAttr := resourceBlock.GetAttribute("load_balancer_arn")
				if lbaAttr.IsResourceBlockReference("aws_lb") {
					referencedBlock, err := ctx.GetReferencedBlock(lbaAttr)
					if err == nil {
						if referencedBlock.HasChild("load_balancer_type") && referencedBlock.GetAttribute("load_balancer_type").Equals("gateway") {
							return
						}
					} else {
						// didn't find the referenced block, log and move on
						debug.Log(err.Error())
					}
				}
			}

			if protocolAttr := resourceBlock.GetAttribute("protocol"); protocolAttr == nil || (protocolAttr.Type() == cty.String && protocolAttr.Value().AsString() == "HTTP") {

				// check if this is a redirect to HTTPS - if it is, then no problem
				if actionBlock := resourceBlock.GetBlock("default_action"); actionBlock != nil {
					actionTypeAttr := actionBlock.GetAttribute("type")
					if actionTypeAttr != nil && actionTypeAttr.Type() == cty.String && actionTypeAttr.Value().AsString() == "redirect" {
						if redirectBlock := actionBlock.GetBlock("redirect"); redirectBlock != nil {
							redirectProtocolAttr := redirectBlock.GetAttribute("protocol")
							if redirectProtocolAttr != nil && redirectProtocolAttr.Type() == cty.String && redirectProtocolAttr.Value().AsString() == "HTTPS" {
								return
							}
						}
					}
				}

				res := result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", resourceBlock.FullName())).
					WithSeverity(severity.Error)

				if protocolAttr != nil {
					res.WithRange(protocolAttr.Range()).
						WithAttributeAnnotation(protocolAttr)
				} else {
					res.WithRange(resourceBlock.Range())
				}

				set.Add(res)
			}
		},
	})
}
