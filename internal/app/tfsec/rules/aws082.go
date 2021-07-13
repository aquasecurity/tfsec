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

const AWSDontUseDefaultAWSVPC = "AWS082"
const AWSDontUseDefaultAWSVPCDescription = "AWS best practice to not use the default VPC for workflows"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSDontUseDefaultAWSVPC,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_default_vpc"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			set.Add(
				result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' should not exist", resourceBlock.FullName())).
					WithRange(resourceBlock.Range()),
			)
		},
	})
}
