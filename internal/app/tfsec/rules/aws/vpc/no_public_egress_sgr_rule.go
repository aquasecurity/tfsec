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
		LegacyID: "AWS007",
		BadExample: []string{`
 resource "aws_security_group_rule" "bad_example" {
 	type = "egress"
 	cidr_blocks = ["0.0.0.0/0"]
 }
 `},
		GoodExample: []string{`
 resource "aws_security_group_rule" "good_example" {
 	type = "egress"
 	cidr_blocks = ["10.0.0.0/16"]
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_security_group_rule"},
		Base:           vpc.CheckNoPublicEgressSgr,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			typeAttr := resourceBlock.GetAttribute("type")
			if typeAttr.IsNil() || !typeAttr.IsString() || typeAttr.NotEqual("egress") {
				return
			}

			if cidrBlocksAttr := resourceBlock.GetAttribute("cidr_blocks"); cidrBlocksAttr.IsNotNil() {

				if cidr.IsAttributeOpen(cidrBlocksAttr) {
					results.Add("Resource defines a fully open egress security group rule.", cidrBlocksAttr)
				}
			}

			if ipv6CidrBlocksAttr := resourceBlock.GetAttribute("ipv6_cidr_blocks"); ipv6CidrBlocksAttr.IsNotNil() {
				if cidr.IsAttributeOpen(ipv6CidrBlocksAttr) {
					results.Add("Resource defines a fully open egress security group rule.", ipv6CidrBlocksAttr)
				}
			}

			return results
		},
	})
}
