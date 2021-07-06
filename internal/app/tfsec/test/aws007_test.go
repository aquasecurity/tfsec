package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSOpenEgressSecurityGroupRule(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group_rule egress on 0.0.0.0/0",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["0.0.0.0/0"]
}`,
			mustIncludeResultCode: rules.AWSOpenEgressSecurityGroupRule,
		},
		{
			name: "check aws_security_group_rule egress on 0.0.0.0/0 in list",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16", "0.0.0.0/0"]
}`,
			mustIncludeResultCode: rules.AWSOpenEgressSecurityGroupRule,
		},
		{
			name: "check aws_security_group_rule egress on 10.0.0.0/16",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
}`,
			mustExcludeResultCode: rules.AWSOpenEgressSecurityGroupRule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
