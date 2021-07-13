package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_network_acl_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			egressAttr := resourceBlock.GetAttribute("egress")
			actionAttr := resourceBlock.GetAttribute("rule_action")
			protoAttr := resourceBlock.GetAttribute("protocol")

			if egressAttr != nil && egressAttr.IsTrue() {
				return
			}

			if actionAttr != nil && !actionAttr.Equals("allow") {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr != nil {

				if isOpenCidr(cidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return
					} else {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", resourceBlock.FullName())).
								WithRange(cidrBlockAttr.Range()),
						)
					}
				}

			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr != nil {

				if isOpenCidr(ipv6CidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return
					} else {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a Network ACL rule that allows specific ingress ports from anywhere.", resourceBlock.FullName())).
								WithRange(ipv6CidrBlockAttr.Range()).
								WithAttributeAnnotation(ipv6CidrBlockAttr),
						)
					}
				}

			}

		},
	})
}
