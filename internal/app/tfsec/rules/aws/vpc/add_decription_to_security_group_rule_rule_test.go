package vpc

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSMissingDescriptionForSecurityGroupRule(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group-rule"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group_rule without description",
			source: `
 resource "aws_security_group_rule" "my-rule" {
 	
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_security_group_rule with description",
			source: `
 resource "aws_security_group_rule" "my-rule" {
 	description = "this is a group for allowing shiz"
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
