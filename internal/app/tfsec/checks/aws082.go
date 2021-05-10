package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSDontUseDefaultAWSVPC scanner.RuleCode = "AWS082"
const AWSDontUseDefaultAWSVPCDescription scanner.RuleSummary = "It is AWS best practice to not use the default VPC for workflows"
const AWSDontUseDefaultAWSVPCImpact = "The default VPC does not have critical security features applied"
const AWSDontUseDefaultAWSVPCResolution = "Create a non-default vpc for resources to be created in"
const AWSDontUseDefaultAWSVPCExplanation = `
Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.
`
const AWSDontUseDefaultAWSVPCBadExample = `
resource "aws_default_vpc" "default" {
	tags = {
	  Name = "Default VPC"
	}
  }
`
const AWSDontUseDefaultAWSVPCGoodExample = `
# no aws default vpc present
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSDontUseDefaultAWSVPC,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSDontUseDefaultAWSVPCDescription,
			Explanation: AWSDontUseDefaultAWSVPCExplanation,
			Impact:      AWSDontUseDefaultAWSVPCImpact,
			Resolution:  AWSDontUseDefaultAWSVPCResolution,
			BadExample:  AWSDontUseDefaultAWSVPCBadExample,
			GoodExample: AWSDontUseDefaultAWSVPCGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc",
				"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_default_vpc"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			return []scanner.Result{
				check.NewResult(
					fmt.Sprintf("Resource '%s' should not exist", block.FullName()),
					block.Range(),
					scanner.SeverityError,
				),
			}
		},
	})
}
