package vpc

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSOpenIngressNetworkACLRule(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress"

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
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied with all protocol",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "all"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied with all protocol using -1",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = -1
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied with all protocol using -1 string",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  protocol       = "-1"
  from_port      = 22
  to_port        = 22
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
resource "aws_network_acl_rule" "my-rule" {
  egress         = false
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
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
  protocol       = "tcp"
  from_port      = 22
  to_port        = 22
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
