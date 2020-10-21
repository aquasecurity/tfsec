package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSPlainHTTP scanner.RuleCode = "AWS004"
const AWSPlainHTTPDescription scanner.RuleSummary = "Use of plain HTTP."
const AWSPlainHTTPExplanation = `
Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
`
const AWSPlainHTTPBadExample = `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
}
`
const AWSPlainHTTPGoodExample = `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTPS"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSPlainHTTP,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSPlainHTTPDescription,
			Explanation: AWSPlainHTTPExplanation,
			BadExample:  AWSPlainHTTPBadExample,
			GoodExample: AWSPlainHTTPGoodExample,
			Links: []string{
				"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_lb_listener", "aws_alb_listener"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if protocolAttr := block.GetAttribute("protocol"); protocolAttr == nil || (protocolAttr.Type() == cty.String && protocolAttr.Value().AsString() == "HTTP") {
				// check if this is a redirect to HTTPS - if it is, then no problem
				if actionBlock := block.GetBlock("default_action"); actionBlock != nil {
					actionTypeAttr := actionBlock.GetAttribute("type")
					if actionTypeAttr != nil && actionTypeAttr.Type() == cty.String && actionTypeAttr.Value().AsString() == "redirect" {
						if redirectBlock := actionBlock.GetBlock("redirect"); redirectBlock != nil {
							redirectProtocolAttr := redirectBlock.GetAttribute("protocol")
							if redirectProtocolAttr != nil && redirectProtocolAttr.Type() == cty.String && redirectProtocolAttr.Value().AsString() == "HTTPS" {
								return nil
							}
						}
					}
				}
				reportRange := block.Range()
				if protocolAttr != nil {
					reportRange = protocolAttr.Range()
				}
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", block.FullName()),
						reportRange,
						protocolAttr,
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
