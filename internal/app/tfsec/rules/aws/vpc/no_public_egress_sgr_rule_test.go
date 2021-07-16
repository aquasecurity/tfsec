package vpc

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSOpenEgressSecurityGroupRule(t *testing.T) {
	expectedCode := "aws-vpc-no-public-egress-sgr"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group_rule egress on 0.0.0.0/0 in list",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16", "0.0.0.0/0"]
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group_rule egress on 10.0.0.0/16",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
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
