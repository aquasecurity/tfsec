package vpc

import (
	"github.com/aquasecurity/defsec/rules/aws/vpc"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS050",
		BadExample: []string{`
 resource "aws_network_acl" "bar" {
 }
  
 resource "aws_network_acl_rule" "bad_example" {
   network_acl_id = aws_network_acl.bar.id
   egress         = false
   protocol       = "all"
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }
 `},
		GoodExample: []string{`
 resource "aws_network_acl" "bar" {
 }

 resource "aws_network_acl_rule" "good_example" {
   network_acl_id = aws_network_acl.bar.id
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
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_network_acl_rule"},
		Base:           vpc.CheckNoExcessivePortAccess,
	})
}
