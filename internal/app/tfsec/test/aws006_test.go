package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSOpenIngressSecurityGroupRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group_rule ingress on 0.0.0.0/0",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "ingress"
	cidr_blocks = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: rules.AWSOpenIngressSecurityGroupRule,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
resource "aws_security_group_rule" "github" {
  description = "HTTPS (GitHub)"
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = var.blocks

  security_group_id = aws_security_group.sg.id
}

variable "blocks" {
	default=["0.0.0.0/0"]
}

`,
			mustIncludeResultCode: rules.AWSOpenIngressSecurityGroupRule,
		},
		{
			name: "check aws_security_group_rule ingress on ::/0",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "ingress"
	ipv6_cidr_blocks = ["::/0"]
}`,
			mustIncludeResultCode: rules.AWSOpenIngressSecurityGroupRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
