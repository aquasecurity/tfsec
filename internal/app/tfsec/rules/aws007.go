package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSOpenEgressSecurityGroupRule = "AWS007"
const AWSOpenEgressSecurityGroupRuleDescription = "An egress security group rule allows traffic to /0."
const AWSOpenEgressSecurityGroupRuleImpact = "Your port is egressing data to the internet"
const AWSOpenEgressSecurityGroupRuleResolution = "Set a more restrictive cidr range"
const AWSOpenEgressSecurityGroupRuleExplanation = `
Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
`
const AWSOpenEgressSecurityGroupRuleBadExample = `
resource "aws_security_group_rule" "bad_example" {
	type = "egress"
	cidr_blocks = ["0.0.0.0/0"]
}
`
const AWSOpenEgressSecurityGroupRuleGoodExample = `
resource "aws_security_group_rule" "good_example" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenEgressSecurityGroupRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenEgressSecurityGroupRuleDescription,
			Explanation: AWSOpenEgressSecurityGroupRuleExplanation,
			Impact:      AWSOpenEgressSecurityGroupRuleImpact,
			Resolution:  AWSOpenEgressSecurityGroupRuleResolution,
			BadExample:  AWSOpenEgressSecurityGroupRuleBadExample,
			GoodExample: AWSOpenEgressSecurityGroupRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			typeAttr := resourceBlock.GetAttribute("type")
			if typeAttr == nil || typeAttr.Type() != cty.String {
				return
			}

			if typeAttr.Value().AsString() != "egress" {
				return
			}

			if cidrBlocksAttr := resourceBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

				if isOpenCidr(cidrBlocksAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", resourceBlock.FullName())).
							WithRange(cidrBlocksAttr.Range()).
							WithAttributeAnnotation(cidrBlocksAttr),
					)
				}
			}

			if ipv6CidrBlocksAttr := resourceBlock.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {

				if isOpenCidr(ipv6CidrBlocksAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open egress security group rule.", resourceBlock.FullName())).
							WithRange(ipv6CidrBlocksAttr.Range()).
							WithAttributeAnnotation(ipv6CidrBlocksAttr),
					)
				}
			}
		},
	})
}
