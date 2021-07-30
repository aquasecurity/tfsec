package vpc

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSOpenIngressSecurityGroup(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress-sg"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group ingress on 0.0.0.0/0",
			source: `
		resource "aws_security_group" "my-group" {
			ingress {
				cidr_blocks = ["0.0.0.0/0"]
			}
		}`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group ingress on ::/0",
			source: `
		resource "aws_security_group" "my-group" {
			ingress {
				ipv6_cidr_blocks = ["0.0.0.0/0"]
			}
		}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group ingress on 10.10.0.0/16",
			source: `
		resource "aws_security_group" "my-group" {
			ingress {
				ipv6_cidr_blocks = ["10.10.0.0/16"]
			}
		}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
