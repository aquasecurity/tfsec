package vpc
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSMissingDescriptionForSecurityGroup(t *testing.T) {
// 	expectedCode := "aws-vpc-add-decription-to-security-group"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "check aws_security_group without description",
// 			source: `
// resource "aws_security_group" "my-group" {
// 	
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_security_group_rule without description",
// 			source: `
// resource "aws_security_group_rule" "my-rule" {
// 	
// }`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_security_group with description",
// 			source: `
// resource "aws_security_group" "my-group" {
// 	description = "this is a group for allowing shiz"
// }`,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "check aws_security_group_rule with description",
// 			source: `
// resource "aws_security_group_rule" "my-rule" {
// 	description = "this is a group for allowing shiz"
// }`,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
