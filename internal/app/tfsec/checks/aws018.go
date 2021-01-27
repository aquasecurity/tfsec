package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

// AWSNoDescriptionInSecurityGroup See https://github.com/tfsec/tfsec#included-checks for check info
const AWSNoDescriptionInSecurityGroup scanner.RuleCode = "AWS018"
const AWSNoDescriptionInSecurityGroupDescription scanner.RuleSummary = "Missing description for security group/security group rule."
const AWSNoDescriptionInSecurityGroupExplanation = `
Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.
`
const AWSNoDescriptionInSecurityGroupBadExample = `
resource "aws_security_group" "http" {
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
resource "aws_security_group" "http" {
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
	scanner.RegisterCheck(scanner.Check{
		Code: AWSNoDescriptionInSecurityGroup,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSNoDescriptionInSecurityGroupDescription,
			Explanation: AWSNoDescriptionInSecurityGroupExplanation,
			BadExample:  AWSNoDescriptionInSecurityGroupBadExample,
			GoodExample: AWSNoDescriptionInSecurityGroupGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
				"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group", "aws_security_group_rule"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			descriptionAttr := block.GetAttribute("description")
			if descriptionAttr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should include a description for auditing purposes.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			if descriptionAttr.Type() == cty.String && descriptionAttr.Value().AsString() == "" {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' should include a non-empty description for auditing purposes.", block.FullName()),
						descriptionAttr.Range(),
						descriptionAttr,
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
