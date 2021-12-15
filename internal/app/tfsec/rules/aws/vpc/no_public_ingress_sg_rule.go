package vpc

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS008",
		BadExample: []string{`
 resource "aws_security_group" "bad_example" {
 	ingress {
 		cidr_blocks = ["0.0.0.0/0"]
 	}
 }
 `},
		GoodExample: []string{`
 resource "aws_security_group" "good_example" {
 	ingress {
 		cidr_blocks = ["1.2.3.4/32"]
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			for _, directionBlock := range resourceBlock.GetBlocks("ingress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr.IsNotNil() {

					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						results.Add("Resource defines a fully open ingress security group.", ?)
					}
				}

				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr.IsNotNil() {

					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						results.Add("Resource defines a fully open ingress security group.", ?)
					}
				}
			}
			return results
		},
	})
}
