package vpc

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/cidr"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS009",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group"},
		Base:           vpc.CheckNoPublicEgressSgr,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			for _, directionBlock := range resourceBlock.GetBlocks("egress") {
				if cidrBlocksAttr := directionBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr.IsNotNil() {
					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						results.Add("Resource defines a fully open egress security group.", cidrBlocksAttr)
					}
				}
				if cidrBlocksAttr := directionBlock.GetAttribute("ipv6_cidr_blocks"); cidrBlocksAttr.IsNotNil() {
					if cidr.IsAttributeOpen(cidrBlocksAttr) {
						results.Add("Resource defines a fully open egress security group.", cidrBlocksAttr)
					}
				}
			}
			return results
		},
	})
}
