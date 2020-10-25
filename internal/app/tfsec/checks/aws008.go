package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSOpenIngressSecurityGroupInlineRule scanner.RuleCode = "AWS008"
const AWSOpenIngressSecurityGroupInlineRuleDescription scanner.RuleSummary = "An inline ingress security group rule allows traffic from `/0`."
const AWSOpenIngressSecurityGroupInlineRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenIngressSecurityGroupInlineRuleBadExample = `
resource "aws_security_group" "my-group" {
	ingress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`
const AWSOpenIngressSecurityGroupInlineRuleGoodExample = `
resource "aws_security_group" "my-group" {
	ingress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenIngressSecurityGroupInlineRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOpenIngressSecurityGroupInlineRuleDescription,
			Explanation: AWSOpenIngressSecurityGroupInlineRuleExplanation,
			BadExample:  AWSOpenIngressSecurityGroupInlineRuleBadExample,
			GoodExample: AWSOpenIngressSecurityGroupInlineRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, directionBlock := range block.GetBlocks("ingress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr, check.Provider) {
						results = append(results,
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", block.FullName()),
								cidrBlocksAttr.Range(),
								scanner.SeverityWarning,
							),
						)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr, check.Provider) {
						results = append(results,
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", block.FullName()),
								cidrBlocksAttr.Range(),
								scanner.SeverityWarning,
							),
						)
					}
				}
			}

			return results
		},
	})
}
