package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

const AWSOpenIngressNetworkACLRule = "AWS049"
const AWSOpenIngressNetworkACLRuleDescription = "An ingress Network ACL rule allows specific ports from /0."
const AWSOpenIngressNetworkACLRuleImpact = "The ports are exposed for ingressing data to the internet"
const AWSOpenIngressNetworkACLRuleResolution = "Set a more restrictive cidr range"
const AWSOpenIngressNetworkACLRuleExplanation = `
Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.

`
const AWSOpenIngressNetworkACLRuleBadExample = `
resource "aws_network_acl_rule" "bad_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`
const AWSOpenIngressNetworkACLRuleGoodExample = `
resource "aws_network_acl_rule" "good_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenIngressNetworkACLRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenIngressNetworkACLRuleDescription,
			Impact:      AWSOpenIngressNetworkACLRuleImpact,
			Resolution:  AWSOpenIngressNetworkACLRuleResolution,
			Explanation: AWSOpenIngressNetworkACLRuleExplanation,
			BadExample:  AWSOpenIngressNetworkACLRuleBadExample,
			GoodExample: AWSOpenIngressNetworkACLRuleGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_network_acl_rule"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			egressAttr := block.GetAttribute("egress")
			actionAttr := block.GetAttribute("rule_action")
			protoAttr := block.GetAttribute("protocol")

			if egressAttr.Type() == cty.Bool && egressAttr.Value().True() {
			}

			if actionAttr == nil || actionAttr.Type() != cty.String {
			}

			if actionAttr.Value().AsString() != "allow" {
			}

			if cidrBlockAttr := block.GetAttribute("cidr_block"); cidrBlockAttr != nil {

				if isOpenCidr(cidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
					} else {
						set.Add(
							result.New().
								WithDescription(fmt.Sprintf("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", block.FullName())).
								WithRange(cidrBlockAttr.Range()).
								WithSeverity(severity.Warning),
						)
					}
				}

			}

			if ipv6CidrBlockAttr := block.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr != nil {

				if isOpenCidr(ipv6CidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
					} else {
						set.Add(
							result.New().
								WithDescription(fmt.Sprintf("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", block.FullName())).
								WithRange(ipv6CidrBlockAttr.Range()).
								WithAttributeAnnotation(ipv6CidrBlockAttr).
								WithSeverity(severity.Warning),
						)
					}
				}

			}

		},
	})
}
