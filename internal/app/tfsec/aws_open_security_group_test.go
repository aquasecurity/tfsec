package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSOpenSecurityGroup(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name: "check aws_security_group ingress on 0.0.0.0/0",
			source: `
resource "aws_security_group" "my-group" {
	ingress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}`,
			mustIncludeResultCode: checks.AWSOpenIngressSecurityGroupInlineRule,
		},
		{
			name: "check aws_security_group egress on 0.0.0.0/0",
			source: `
resource "aws_security_group" "my-group" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}`,
			mustIncludeResultCode: checks.AWSOpenEgressSecurityGroupInlineRule,
		},
		{
			name: "check aws_security_group egress on 0.0.0.0/0 in list",
			source: `
resource "aws_security_group" "my-group" {
	egress {
		cidr_blocks = ["10.0.0.0/16", "0.0.0.0/0"]
	}
}`,
			mustIncludeResultCode: checks.AWSOpenEgressSecurityGroupInlineRule,
		},
		{
			name: "check aws_security_group egress on 10.0.0.0/16",
			source: `
resource "aws_security_group" "my-group" {
	egress {
		cidr_blocks = ["10.0.0.0/16"]
	}
}`,
			mustExcludeResultCode: checks.AWSOpenEgressSecurityGroupInlineRule,
		},
		{
			name: "check dynamic blocks using for_each",
			source: `
variable "vpc_cidr_block" {}
variable "ingress_filter" { default = "ALLOW_ALL" }

locals {
  name = "example-lb"
}

resource "aws_security_group" "alb" {
  count = var.enabled ? 1 : 0

  name        = "${local.name}-sg"
  description = "Security group for ${local.name} load balancer"

  vpc_id = var.vpc_id

  egress {

    cidr_blocks = [
      "10.0.0.0/16"
    ]

    from_port   = 0
    to_port     = 0
    protocol    = -1
    description = "Egress to VPC"
  }

  dynamic "ingress" {
    for_each = var.ingress_filter == "ALLOW_ALL" ? [1] : []
    content {

      cidr_blocks = [
        "0.0.0.0/0"
      ]

      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "Allow all ingress for TLS"
    }
  }
}
			`,
			mustIncludeResultCode: checks.AWSOpenIngressSecurityGroupInlineRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
