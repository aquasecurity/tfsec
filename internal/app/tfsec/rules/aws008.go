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

const AWSOpenIngressSecurityGroupInlineRule = "AWS008"
const AWSOpenIngressSecurityGroupInlineRuleDescription = "An inline ingress security group rule allows traffic from /0."
const AWSOpenIngressSecurityGroupInlineRuleImpact = "The port is exposed for ingress from the internet"
const AWSOpenIngressSecurityGroupInlineRuleResolution = "Set a more restrictive cidr range"
const AWSOpenIngressSecurityGroupInlineRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenIngressSecurityGroupInlineRuleBadExample = `
resource "aws_security_group" "bad_example" {
	ingress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`
const AWSOpenIngressSecurityGroupInlineRuleGoodExample = `
resource "aws_security_group" "good_example" {
	ingress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenIngressSecurityGroupInlineRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenIngressSecurityGroupInlineRuleDescription,
			Impact:      AWSOpenIngressSecurityGroupInlineRuleImpact,
			Resolution:  AWSOpenIngressSecurityGroupInlineRuleResolution,
			Explanation: AWSOpenIngressSecurityGroupInlineRuleExplanation,
			BadExample:  AWSOpenIngressSecurityGroupInlineRuleBadExample,
			GoodExample: AWSOpenIngressSecurityGroupInlineRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(resultSet result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			for _, directionBlock := range resourceBlock.GetBlocks("ingress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr) {
						resultSet.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", resourceBlock.FullName())).
								WithRange(cidrBlocksAttr.Range()).
								WithAttributeAnnotation(cidrBlocksAttr),
						)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr) {
						resultSet.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open ingress security group.", resourceBlock.FullName())).
								WithRange(cidrBlocksAttr.Range()),
						)
					}
				}
			}
		},
	})
}
