package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSResourceHasPublicIP scanner.RuleCode = "AWS012"
const AWSResourceHasPublicIPDescription scanner.RuleSummary = "A resource has a public IP address."
const AWSResourceHasPublicIPImpact = "The instance or configuration is publically accessible"
const AWSResourceHasPublicIPResolution = "Set the instance to not be publically accessible"
const AWSResourceHasPublicIPExplanation = `
You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. 
`
const AWSResourceHasPublicIPBadExample = `
resource "aws_launch_configuration" "bad_example" {
	associate_public_ip_address = true
}
`
const AWSResourceHasPublicIPGoodExample = `
resource "aws_launch_configuration" "good_example" {
	associate_public_ip_address = false
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSResourceHasPublicIP,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSResourceHasPublicIPDescription,
			Impact:      AWSResourceHasPublicIPImpact,
			Resolution:  AWSResourceHasPublicIPResolution,
			Explanation: AWSResourceHasPublicIPExplanation,
			BadExample:  AWSResourceHasPublicIPBadExample,
			GoodExample: AWSResourceHasPublicIPGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_launch_configuration", "aws_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if publicAttr := block.GetAttribute("associate_public_ip_address"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has a public IP address associated.", block.FullName()),
							publicAttr.Range(),
							publicAttr,
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
