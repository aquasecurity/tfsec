package vpc

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
 resource "aws_network_acl" "bar" {
 }

 resource "aws_network_acl_rule" "my-rule" {
   network_acl_id = aws_network_acl.bar.id
   egress         = false
   protocol       = "all"
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }`,
			mustIncludeResultCode: expectedCode,
		}, {
			name: "check aws_network_acl_rule ingress on 0.0.0.0/0 implied egress",
			source: `
 resource "aws_network_acl" "bar" {
 }
		   
 resource "aws_network_acl_rule" "my-rule" {
   network_acl_id = aws_network_acl.bar.id
   protocol       = "all"
   rule_action    = "allow"
   cidr_block     = "0.0.0.0/0"
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check variable containing 0.0.0.0/0",
			source: `
 resource "aws_network_acl" "bar" {
 }

 resource "aws_network_acl_rule" "my-rule" {
   network_acl_id = aws_network_acl.bar.id
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
 resource "aws_network_acl" "bar" {
 }
		   
 resource "aws_network_acl_rule" "my-rule" {
   network_acl_id = aws_network_acl.bar.id
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
