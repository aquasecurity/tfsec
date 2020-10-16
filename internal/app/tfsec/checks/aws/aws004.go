package aws

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSPlainHTTP See https://github.com/tfsec/tfsec#included-checks for check info
const AWSPlainHTTP scanner.RuleID = "AWS004"
const AWSPlainHTTPDescription scanner.RuleSummary = "Use of plain HTTP."
const AWSPlainHTTPExplanation = `

`
const AWSPlainHTTPBadExample = `

`
const AWSPlainHTTPGoodExample = `

`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSPlainHTTP,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSPlainHTTPDescription,
			Explanation: AWSPlainHTTPExplanation,
			BadExample:  AWSPlainHTTPBadExample,
			GoodExample: AWSPlainHTTPGoodExample,
			Links:       []string{},
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
						fmt.Sprintf("Resource '%s' uses plain HTTP instead of HTTPS.", block.Name()),
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
