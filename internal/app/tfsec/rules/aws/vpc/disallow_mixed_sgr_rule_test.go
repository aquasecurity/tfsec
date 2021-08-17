package vpc

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
	"testing"
)

func Test_AWSDisallowMixedSecurityGroupRule(t *testing.T) {
	expectedCode := "aws-vpc-disallow-mixed-sgr"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check mixed aws_security_group_rule and inline egress & ingress on security_group",
			source: `
resource "aws_security_group_rule" "my-security-group-rule" {
  	security_group_id = aws_security_group.my-security-group.id
	type = "ingress"
	cidr_blocks = ["172.31.0.0/16"]
}

resource "aws_security_group" "my-security-group" {
	ingress {
		cidr_blocks = ["10.0.0.0/16"]
	}
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check defined in aws_security_group_rule only",
			source: `
resource "aws_security_group_rule" "my-security-group-rule" {
  	security_group_id = aws_security_group.bad_example_sg.id
	type = "ingress"
	cidr_blocks = ["172.31.0.0/16", "10.0.0.0/16"]
}

resource "aws_security_group" "my-security-group" {
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check defined in aws_security_group only",
			source: `
resource "aws_security_group" "my-security-group" {
	ingress {
		cidr_blocks = ["10.0.0.0/16"]
	}
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check applicable only on co-related aws_security_group and aws_security_group_rule",
			source: `
resource "aws_security_group_rule" "my-security-group-rule" {
  	security_group_id = aws_security_group.my-security-group-a.id
	type = "ingress"
	cidr_blocks = ["172.31.0.0/16"]
}

resource "aws_security_group" "my-security-group-a" {
}

resource "aws_security_group" "my-security-group-b" {
	ingress {
		cidr_blocks = ["10.0.0.0/16"]
	}
	egress {
		cidr_blocks = ["0.0.0.0/0"]
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
