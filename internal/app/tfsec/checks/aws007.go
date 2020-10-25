package checks

import (
	"fmt"
	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSOpenEgressSecurityGroupRule scanner.RuleCode = "AWS007"
const AWSOpenEgressSecurityGroupRuleDescription scanner.RuleSummary = "An egress security group rule allows traffic to `/0`."
const AWSOpenEgressSecurityGroupRuleExplanation = `
Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
`
const AWSOpenEgressSecurityGroupRuleBadExample = `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["0.0.0.0/0"]
}
`
const AWSOpenEgressSecurityGroupRuleGoodExample = `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenEgressSecurityGroupRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOpenEgressSecurityGroupRuleDescription,
			Explanation: AWSOpenEgressSecurityGroupRuleExplanation,
			BadExample:  AWSOpenEgressSecurityGroupRuleBadExample,
			GoodExample: AWSOpenEgressSecurityGroupRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			typeAttr := block.GetAttribute("type")
			if typeAttr == nil || typeAttr.Type() != cty.String {
				return nil
			}

			if typeAttr.Value().AsString() != "egress" {
				return nil
			}

			if cidrBlocksAttr := block.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if isOpenCidr(cidrBlocksAttr, check.Provider) {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", block.FullName()),
							cidrBlocksAttr.Range(),
							cidrBlocksAttr,
							scanner.SeverityWarning,
						),
					}
				}
			}

			if ipv6CidrBlocksAttr := block.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {

				if isOpenCidr(ipv6CidrBlocksAttr, check.Provider) {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", block.FullName()),
							ipv6CidrBlocksAttr.Range(),
							ipv6CidrBlocksAttr,
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}
