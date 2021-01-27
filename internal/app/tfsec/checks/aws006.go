package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSOpenIngressSecurityGroupRule scanner.RuleCode = "AWS006"
const AWSOpenIngressSecurityGroupRuleDescription scanner.RuleSummary = "An ingress security group rule allows traffic from `/0`."
const AWSOpenIngressSecurityGroupRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenIngressSecurityGroupRuleBadExample = `
resource "aws_security_group_rule" "my-rule" {
	type = "ingress"
	cidr_blocks = ["0.0.0.0/0"]
}
`
const AWSOpenIngressSecurityGroupRuleGoodExample = `
resource "aws_security_group_rule" "my-rule" {
	type = "ingress"
	cidr_blocks = ["10.0.0.0/16"]
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenIngressSecurityGroupRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOpenIngressSecurityGroupRuleDescription,
			Explanation: AWSOpenIngressSecurityGroupRuleExplanation,
			BadExample:  AWSOpenIngressSecurityGroupRuleBadExample,
			GoodExample: AWSOpenIngressSecurityGroupRuleGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
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

			if typeAttr.Value().AsString() != "ingress" {
				return nil
			}

			if cidrBlocksAttr := block.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if isOpenCidr(cidrBlocksAttr, check.Provider) {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' defines a fully open ingress security group rule.", block.FullName()),
							cidrBlocksAttr.Range(),
							scanner.SeverityWarning,
						),
					}
				}

			}

			if ipv6CidrBlocksAttr := block.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {

				if isOpenCidr(ipv6CidrBlocksAttr, check.Provider) {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' defines a fully open ingress security group rule.", block.FullName()),
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
