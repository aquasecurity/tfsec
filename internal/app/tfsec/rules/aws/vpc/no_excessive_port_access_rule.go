package vpc

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS050",
		BadExample: []string{`
 resource "aws_network_acl_rule" "bad_example" {
   egress         = false
   protocol       = "all"
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
   cidr_block     = "0.0.0.0/0"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port",
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_network_acl_rule"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			egressAttr := resourceBlock.GetAttribute("egress")
			actionAttr := resourceBlock.GetAttribute("rule_action")
			protoAttr := resourceBlock.GetAttribute("protocol")

			if egressAttr.IsNotNil() && egressAttr.IsTrue() {
				return
			}

			if actionAttr.IsNil() || !actionAttr.IsString() || actionAttr.NotEqual("allow") {
				return
			}

			if cidrBlockAttr := resourceBlock.GetAttribute("cidr_block"); cidrBlockAttr.IsNotNil() {
				if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
					results.Add("Resource defines a fully open ingress Network ACL rule with ALL ports open.", ?)
				}
			}

			if ipv6CidrBlockAttr := resourceBlock.GetAttribute("ipv6_cidr_block"); ipv6CidrBlockAttr.IsNotNil() {
				if protoAttr.Value().AsString() == "all" || protoAttr.Value().AsString() == "-1" {
					results.Add("Resource defines a fully open ingress Network ACL rule with ALL ports open.", ?)
				}
			}

			return results
		},
	})
}
