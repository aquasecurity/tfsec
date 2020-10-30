package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AWSOpenAllIngressNetworkACLRule scanner.RuleCode = "AWS050"
const AWSOpenAllIngressNetworkACLRuleDescription scanner.RuleSummary = "An ingress Network ACL rule allows ALL ports from `/0`."
const AWSOpenAllIngressNetworkACLRuleExplanation = `
Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible, and ensure that you specify required ports.

`
const AWSOpenAllIngressNetworkACLRuleBadExample = `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`
const AWSOpenAllIngressNetworkACLRuleGoodExample = `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSOpenAllIngressNetworkACLRule,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSOpenAllIngressNetworkACLRuleDescription,
			Explanation: AWSOpenAllIngressNetworkACLRuleExplanation,
			BadExample:  AWSOpenAllIngressNetworkACLRuleBadExample,
			GoodExample: AWSOpenAllIngressNetworkACLRuleGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_network_acl_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			egressAttr := block.GetAttribute("egress")
			actionAttr := block.GetAttribute("rule_action")
			protoAttr := block.GetAttribute("protocol")

			if egressAttr.Type() == cty.Bool && egressAttr.Value().True() {
				return nil
			}

			if actionAttr == nil || actionAttr.Type() != cty.String {
				return nil
			}

			if actionAttr.Value().AsString() != "allow" {
				return nil
			}

			if cidrBlockAttr := block.GetAttribute("cidr_block"); cidrBlockAttr != nil {

				if isOpenCidr(cidrBlockAttr, check.Provider) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", block.FullName()),
								cidrBlockAttr.Range(),
								scanner.SeverityError,
							),
						}
					} else {
						return nil
					}
				}

			}

			if ipv6CidrBlockAttr := block.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr != nil {

				if isOpenCidr(ipv6CidrBlockAttr, check.Provider) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return []scanner.Result{
							check.NewResultWithValueAnnotation(
								fmt.Sprintf("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", block.FullName()),
								ipv6CidrBlockAttr.Range(),
								ipv6CidrBlockAttr,
								scanner.SeverityError,
							),
						}
					} else {
						return nil
					}
				}

			}

			return nil
		},
	})
}
