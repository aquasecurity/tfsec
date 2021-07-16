package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "aws_default_vpc" "this" {}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is literal 1",
			source: `
			resource "aws_default_vpc" "this" {
				count = 1
			}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is literal 99",
			source: `
			resource "aws_default_vpc" "this" {
				count = 99
			}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is literal 0",
			source: `
			resource "aws_default_vpc" "this" {
				count = 0
			}
`,
			mustExcludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is 0 from variable",
			source: `
			variable "count" {
				default = 0
			}
			resource "aws_default_vpc" "this" {
				count = var.count
			}
`,
			mustExcludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is 1 from variable",
			source: `
			variable "count" {
				default = 1
			}
			resource "aws_default_vpc" "this" {
				count =  var.count
			}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is 1 from variable without default",
			source: `
			variable "count" {
			}
			resource "aws_default_vpc" "this" {
				count =  var.count
			}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is 0 from conditional",
			source: `
			variable "enabled" {
				default = false
			}
			resource "aws_default_vpc" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			mustExcludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "count is 1 from conditional",
			source: `
			variable "enabled" {
				default = true
			}
			resource "aws_default_vpc" "this" {
				count =  var.enabled ? 1 : 0
			}
`,
			mustIncludeResultCode: "aws-vpc-no-default-vpc",
		},
		{
			name: "Test use of count.index",
			source: `
resource "aws_security_group_rule" "trust-rules-dev" {
	count = 1
	description = var.trust-sg-rules[count.index]["description"]
	type = "ingress"
	protocol = "tcp"
	cidr_blocks = ["0.0.0.0/2"]
	to_port = var.trust-sg-rules[count.index]["to_port"]
	from_port = 10
	security_group_id = aws_security_group.trust-rules-dev.id
}
	
resource "aws_security_group" "trust-rules-dev" {
	description = "description"
}
	
variable "trust-sg-rules" {
	description = "A list of maps that creates a number of sg"
	type = list(map(string))
	
	default = [
		{
			description = "Allow egress of http traffic"
			from_port = "80"
			to_port = "80"
			type = "egress"
		}
	]
}
			`,
			mustExcludeResultCode: "AWS018",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
