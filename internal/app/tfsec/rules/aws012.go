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

const AWSResourceHasPublicIP = "AWS012"
const AWSResourceHasPublicIPDescription = "A resource has a public IP address."
const AWSResourceHasPublicIPImpact = "The instance or configuration is publicly accessible"
const AWSResourceHasPublicIPResolution = "Set the instance to not be publicly accessible"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSResourceHasPublicIP,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_launch_configuration", "aws_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if publicAttr := resourceBlock.GetAttribute("associate_public_ip_address"); publicAttr != nil && publicAttr.Type() == cty.Bool {
				if publicAttr.Value().True() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' has a public IP address associated.", resourceBlock.FullName())).
							WithRange(publicAttr.Range()).
							WithAttributeAnnotation(publicAttr),
					)
				}
			}

		},
	})
}
