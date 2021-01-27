package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSOpenIngressNetworkACLRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: checks.AWSOpenIngressNetworkACLRule,
		},{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: checks.AWSOpenIngressNetworkACLRule,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = var.cidr
}

variable "cidr" {
	default="0.0.0.0/0"
}

`,
			mustIncludeResultCode: checks.AWSOpenIngressNetworkACLRule,
		},
		{
			name: "check aws_network_acl_rule ingress on ::/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  ipv6_cidr_block = "::/0"
}`,
			mustIncludeResultCode: checks.AWSOpenIngressNetworkACLRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
