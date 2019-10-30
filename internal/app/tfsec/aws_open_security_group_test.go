package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSOpenSecurityGroup(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode checks.Code
		mustExcludeResultCode checks.Code
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
