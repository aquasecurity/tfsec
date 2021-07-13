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

const AWSOpenIngressSecurityGroupRule = "AWS006"
const AWSOpenIngressSecurityGroupRuleDescription = "An ingress security group rule allows traffic from /0."
const AWSOpenIngressSecurityGroupRuleImpact = "Your port exposed to the internet"
const AWSOpenIngressSecurityGroupRuleResolution = "Set a more restrictive cidr range"
const AWSOpenIngressSecurityGroupRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenIngressSecurityGroupRuleBadExample = `
resource "aws_security_group_rule" "bad_example" {
	type = "ingress"
	cidr_blocks = ["0.0.0.0/0"]
}
`
const AWSOpenIngressSecurityGroupRuleGoodExample = `
resource "aws_security_group_rule" "good_example" {
	type = "ingress"
	cidr_blocks = ["10.0.0.0/16"]
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenIngressSecurityGroupRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenIngressSecurityGroupRuleDescription,
			Explanation: AWSOpenIngressSecurityGroupRuleExplanation,
			Impact:      AWSOpenIngressSecurityGroupRuleImpact,
			Resolution:  AWSOpenIngressSecurityGroupRuleResolution,
			BadExample:  AWSOpenIngressSecurityGroupRuleBadExample,
			GoodExample: AWSOpenIngressSecurityGroupRuleGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
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

			if typeAttr.Value().AsString() != "ingress" {
				return
			}

			if cidrBlocksAttr := resourceBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {
				if isOpenCidr(cidrBlocksAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress security group rule.", resourceBlock.FullName())).
							WithAttributeAnnotation(cidrBlocksAttr).
							WithRange(cidrBlocksAttr.Range()),
					)
				}
			}

			if ipv6CidrBlocksAttr := resourceBlock.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr != nil {
				if isOpenCidr(ipv6CidrBlocksAttr) {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress security group rule.", resourceBlock.FullName())).
							WithRange(ipv6CidrBlocksAttr.Range()).
							WithAttributeAnnotation(ipv6CidrBlocksAttr),
					)
				}

			}
		},
	})
}
