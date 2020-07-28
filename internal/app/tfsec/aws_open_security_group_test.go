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
		{
			name: "check aws_security_group multiple ingress on 0.0.0.0/0",
			source: `
		resource "aws_security_group" "my-group" {
			ingress {
				cidr_blocks = ["10.10.0.32/16"]
			}
			ingress {
				cidr_blocks = ["0.0.0.0/0"]
			}
		}`,
			mustIncludeResultCode: checks.AWSOpenIngressSecurityGroupInlineRule,
		},
		{
			name: "check dynamic values for cidr_blocks",
			source: `
resource "aws_security_group" "sg_dmz" {
  name        = "name"
  description = "g_dmz_desc"
  vpc_id      = "asdf"

  egress {
    from_port   = 25
    to_port     = 25
    protocol    = "tcp"
    cidr_blocks = concat(var.cidr_2, var.cidr_1)
    description = "Email sending to SMTP service"
  }
}

variable "cidr_1" {
  default = ["0.0.0.0/0"]
}
variable "cidr_2" {
  default = ["1.1.1.1/32"]
}
`,
			mustIncludeResultCode: checks.AWSOpenEgressSecurityGroupInlineRule,
		},
		{
			name: "check aws_security_group ingress on ::/0",
			source: `
		resource "aws_security_group" "my-group" {
			ingress {
				ipv6_cidr_blocks = ["0.0.0.0/0"]
			}
		}`,
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
