package vpc

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSOpenAllIngressNetworkACLRule(t *testing.T) {
	expectedCode := "aws-vpc-no-excessive-port-access"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "all"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress with -1 string",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress with -1",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = -1
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.cidr
}

variable "cidr" {
	default="0.0.0.0/0"
}

`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on ::/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  rule_number    = 200
  egress         = false
  protocol       = "all"
  rule_action    = "allow"
  ipv6_cidr_block = "::/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
