package redshift

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Service:   "redshift",
		ShortCode: "add-description-to-security-group",
		Documentation: rule.RuleDocumentation{
			Summary:    "Missing description for security group/security group rule.",
			Impact:     "Descriptions provide context for the firewall rule reasons",
			Resolution: "Add descriptions for all security groups and rules",
			Explanation: `
Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.
`,
			BadExample: []string{`
resource "aws_redshift_security_group" "bad_example" {
  name        = "http"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
`},
			GoodExample: []string{`
resource "aws_redshift_security_group" "good_example" {
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
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
				"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_redshift_security_group"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if resourceBlock.MissingChild("description") {
				set.AddResult().
					WithDescription("Resource '%s' should include a description for auditing purposes.", resourceBlock.FullName())
				return
			}

			descriptionAttr := resourceBlock.GetAttribute("description")
			if descriptionAttr.IsEmpty() {
				set.AddResult().
					WithDescription("Resource '%s' should include a non-empty description for auditing purposes.", resourceBlock.FullName()).
					WithAttribute(descriptionAttr)
			}
		},
	})
}
