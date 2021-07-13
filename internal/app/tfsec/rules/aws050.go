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
	"github.com/zclconf/go-cty/cty"
)

const AWSOpenAllIngressNetworkACLRule = "AWS050"
const AWSOpenAllIngressNetworkACLRuleDescription = "An ingress Network ACL rule allows ALL ports from /0."
const AWSOpenAllIngressNetworkACLRuleImpact = "All ports exposed for egressing data to the internet"
const AWSOpenAllIngressNetworkACLRuleResolution = "Set a more restrictive cidr range"
const AWSOpenAllIngressNetworkACLRuleExplanation = `
Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible, and ensure that you specify required ports.

`
const AWSOpenAllIngressNetworkACLRuleBadExample = `
resource "aws_network_acl_rule" "bad_example" {
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`
const AWSOpenAllIngressNetworkACLRuleGoodExample = `
resource "aws_network_acl_rule" "good_example" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenAllIngressNetworkACLRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenAllIngressNetworkACLRuleDescription,
			Impact:      AWSOpenAllIngressNetworkACLRuleImpact,
			Resolution:  AWSOpenAllIngressNetworkACLRuleResolution,
			Explanation: AWSOpenAllIngressNetworkACLRuleExplanation,
			BadExample:  AWSOpenAllIngressNetworkACLRuleBadExample,
			GoodExample: AWSOpenAllIngressNetworkACLRuleGoodExample,
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

			if actionAttr == nil || actionAttr.Type() != cty.String {
				return
			}

			if actionAttr.Value().AsString() != "allow" {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr != nil {
				if isOpenCidr(cidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", resourceBlock.FullName())).
								WithRange(cidrBlockAttr.Range()).
								WithAttributeAnnotation(cidrBlockAttr),
						)
					}
				}
			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr != nil {
				if isOpenCidr(ipv6CidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress Network ACL rule with ALL ports open.", resourceBlock.FullName())).
								WithRange(ipv6CidrBlockAttr.Range()).
								WithAttributeAnnotation(ipv6CidrBlockAttr),
						)
					}
				}
			}

		},
	})
}
