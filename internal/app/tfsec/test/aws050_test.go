package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSOpenAllIngressNetworkACLRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: rules.AWSOpenAllIngressNetworkACLRule,
		}, {
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: rules.AWSOpenAllIngressNetworkACLRule,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.cidr
}

variable "cidr" {
	default="0.0.0.0/0"
}

`,
			mustIncludeResultCode: rules.AWSOpenAllIngressNetworkACLRule,
		},
		{
			name: "check aws_network_acl_rule ingress on ::/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  rule_number    = 200
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  ipv6_cidr_block = "::/0"
}`,
			mustIncludeResultCode: rules.AWSOpenAllIngressNetworkACLRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
