package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSOpenEgressSecurityGroupInlineRule scanner.RuleCode = "AWS009"
const AWSOpenEgressSecurityGroupInlineRuleDescription scanner.RuleSummary = "An inline egress security group rule allows traffic to `/0`."
const AWSOpenEgressSecurityGroupInlineRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenEgressSecurityGroupInlineRuleBadExample = `
resource "aws_security_group" "my-group" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`
const AWSOpenEgressSecurityGroupInlineRuleGoodExample = `
resource "aws_security_group" "my-group" {
	egress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenEgressSecurityGroupInlineRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOpenEgressSecurityGroupInlineRuleDescription,
			Explanation: AWSOpenEgressSecurityGroupInlineRuleExplanation,
			BadExample:  AWSOpenEgressSecurityGroupInlineRuleBadExample,
			GoodExample: AWSOpenEgressSecurityGroupInlineRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			var results []scanner.Result

			for _, directionBlock := range block.GetBlocks("egress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr, check.Provider) {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.FullName()),
								cidrBlocksAttr.Range(),
								cidrBlocksAttr,
								scanner.SeverityWarning,
							),
						)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr, check.Provider) {
						results = append(results,
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.FullName()),
								cidrBlocksAttr.Range(),
								cidrBlocksAttr,
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
