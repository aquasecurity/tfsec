package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSMissingDescriptionForSecurityGroup(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_security_group without description",
			source: `
resource "aws_security_group" "my-group" {
	
}`,
			mustIncludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group_rule without description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	
}`,
			mustIncludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group with description",
			source: `
resource "aws_security_group" "my-group" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group_rule with description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name:                  "check aws_security_group good example",
			source:                rules.AWSNoDescriptionInSecurityGroupGoodExample,
			mustExcludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
		{
			name:                  "check aws_security_group bad example",
			source:                rules.AWSNoDescriptionInSecurityGroupBadExample,
			mustIncludeResultCode: rules.AWSNoDescriptionInSecurityGroup,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
