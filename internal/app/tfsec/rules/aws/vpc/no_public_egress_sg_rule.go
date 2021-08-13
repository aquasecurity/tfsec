package vpc

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS009",
		Service:   "vpc",
		ShortCode: "no-public-egress-sg",
		Documentation: rule.RuleDocumentation{
			Summary:    "An inline egress security group rule allows traffic to /0.",
			Impact:     "The port is exposed for egressing data to the internet",
			Resolution: "Set a more restrictive cidr range",
			Explanation: `
Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
`,
			BadExample: []string{`
resource "aws_security_group" "bad_example" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`},
			GoodExample: []string{`
resource "aws_security_group" "good_example" {
	egress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			for _, directionBlock := range resourceBlock.GetBlocks("egress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr.IsNotNil() {

					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						set.AddResult().
							WithDescription("Resource '%s' defines a fully open egress security group.", resourceBlock.FullName()).
							WithAttribute(cidrBlocksAttr)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr.IsNotNil() {

					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						set.AddResult().
							WithDescription("Resource '%s' defines a fully open egress security group.", resourceBlock.FullName()).
							WithAttribute(cidrBlocksAttr)
					}
				}
			}
		},
	})
}
