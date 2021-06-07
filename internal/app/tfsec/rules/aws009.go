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
)

const AWSOpenEgressSecurityGroupInlineRule = "AWS009"
const AWSOpenEgressSecurityGroupInlineRuleDescription = "An inline egress security group rule allows traffic to /0."
const AWSOpenEgressSecurityGroupInlineRuleImpact = "The port is exposed for egressing data to the internet"
const AWSOpenEgressSecurityGroupInlineRuleResolution = "Set a more restrictive cidr range"
const AWSOpenEgressSecurityGroupInlineRuleExplanation = `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`
const AWSOpenEgressSecurityGroupInlineRuleBadExample = `
resource "aws_security_group" "bad_example" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`
const AWSOpenEgressSecurityGroupInlineRuleGoodExample = `
resource "aws_security_group" "good_example" {
	egress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSOpenEgressSecurityGroupInlineRule,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSOpenEgressSecurityGroupInlineRuleDescription,
			Impact:      AWSOpenEgressSecurityGroupInlineRuleImpact,
			Resolution:  AWSOpenEgressSecurityGroupInlineRuleResolution,
			Explanation: AWSOpenEgressSecurityGroupInlineRuleExplanation,
			BadExample:  AWSOpenEgressSecurityGroupInlineRuleBadExample,
			GoodExample: AWSOpenEgressSecurityGroupInlineRuleGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			for _, directionBlock := range block.GetBlocks("egress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr) {
						set.Add(
							result.New().
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.FullName())).
								WithRange(cidrBlocksAttr.Range()).
								WithAttributeAnnotation(cidrBlocksAttr).
								WithSeverity(severity.Warning),
						)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr != nil {

					if isOpenCidr(cidrBlocksAttr) {
						set.Add(
							result.New().
								WithDescription(fmt.Sprintf("Resource '%s' defines a fully open egress security group.", block.FullName())).
								WithRange(cidrBlocksAttr.Range()).
								WithAttributeAnnotation(cidrBlocksAttr).
								WithSeverity(severity.Warning),
						)
					}
				}
			}
		},
	})
}
