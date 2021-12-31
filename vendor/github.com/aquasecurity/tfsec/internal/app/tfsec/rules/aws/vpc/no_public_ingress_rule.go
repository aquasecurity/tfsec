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
		LegacyID: "AWS049",
		BadExample: []string{`
 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 `},
		GoodExample: []string{`
 resource "aws_network_acl_rule" "good_example" {
   egress         = false
   protocol       = "tcp"
   from_port      = 22
   to_port        = 22
   rule_action    = "allow"
   cidr_block     = "10.0.0.0/16"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#cidr_block",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_network_acl_rule"},
		Base:           vpc.CheckNoPublicIngress,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			egressAttr := resourceBlock.GetAttribute("egress")
			actionAttr := resourceBlock.GetAttribute("rule_action")
			protoAttr := resourceBlock.GetAttribute("protocol")

			if egressAttr.IsNotNil() && egressAttr.IsTrue() {
				return
			}

			if actionAttr.IsNotNil() && actionAttr.NotEqual("allow") {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr.IsNotNil() {

				if cidr.IsAttributeOpen(cidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return
					} else {
						results.Add("Resource defines a Network ACL rule that allows specific ingress ports from anywhere.", cidrBlockAttr)
					}
				}

			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr.IsNotNil() {

				if cidr.IsAttributeOpen(ipv6CidrBlockAttr) {
					if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
						return
					} else {
						results.Add("Resource defines a Network ACL rule that allows specific ingress ports from anywhere.", ipv6CidrBlockAttr)
					}
				}

			}

			return results
		},
	})
}
