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

const AWSNoDescriptionInSecurityGroup = "AWS018"
const AWSNoDescriptionInSecurityGroupDescription = "Missing description for security group/security group rule."
const AWSNoDescriptionInSecurityGroupImpact = "Descriptions provide context for the firewall rule reasons"
const AWSNoDescriptionInSecurityGroupResolution = "Add descriptions for all security groups and rules"
const AWSNoDescriptionInSecurityGroupExplanation = `
Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.
`
const AWSNoDescriptionInSecurityGroupBadExample = `
resource "aws_security_group" "bad_example" {
  name        = "http"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
`
const AWSNoDescriptionInSecurityGroupGoodExample = `
resource "aws_security_group" "good_example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSNoDescriptionInSecurityGroup,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSNoDescriptionInSecurityGroupDescription,
			Impact:      AWSNoDescriptionInSecurityGroupImpact,
			Resolution:  AWSNoDescriptionInSecurityGroupResolution,
			Explanation: AWSNoDescriptionInSecurityGroupExplanation,
			BadExample:  AWSNoDescriptionInSecurityGroupBadExample,
			GoodExample: AWSNoDescriptionInSecurityGroupGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
				"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group", "aws_security_group_rule"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.MissingChild("description") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should include a description for auditing purposes.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			descriptionAttr := resourceBlock.GetAttribute("description")
			if descriptionAttr.IsEmpty() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should include a non-empty description for auditing purposes.", resourceBlock.FullName())).
						WithRange(descriptionAttr.Range()).
						WithAttributeAnnotation(descriptionAttr),
				)
			}
		},
	})
}
