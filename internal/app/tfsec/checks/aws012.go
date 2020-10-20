package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

const AWSResourceHasPublicIP scanner.RuleCode = "AWS012"
const AWSResourceHasPublicIPDescription scanner.RuleSummary = "A resource has a public IP address."
const AWSResourceHasPublicIPExplanation = `
You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. 
`
const AWSResourceHasPublicIPBadExample = `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = true
}
`
const AWSResourceHasPublicIPGoodExample = `
resource "aws_launch_configuration" "my-resource" {
	associate_public_ip_address = false
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSResourceHasPublicIP,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSResourceHasPublicIPDescription,
			Explanation: AWSResourceHasPublicIPExplanation,
			BadExample:  AWSResourceHasPublicIPBadExample,
			GoodExample: AWSResourceHasPublicIPGoodExample,
			Links:       []string{},
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
