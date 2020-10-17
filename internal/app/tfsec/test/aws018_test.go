package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSMissingDescriptionForSecurityGroup(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_security_group without description",
			source: `
resource "aws_security_group" "my-group" {
	
}`,
			mustIncludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group_rule without description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	
}`,
			mustIncludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group with description",
			source: `
resource "aws_security_group" "my-group" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
		{
			name: "check aws_security_group_rule with description",
			source: `
resource "aws_security_group_rule" "my-rule" {
	description = "this is a group for allowing shiz"
}`,
			mustExcludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
		{
			name:                  "check aws_security_group good example",
			source:                checks.AWSNoDescriptionInSecurityGroupGoodExample,
			mustExcludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
		{
			name:                  "check aws_security_group bad example",
			source:                checks.AWSNoDescriptionInSecurityGroupBadExample,
			mustIncludeResultCode: checks.AWSNoDescriptionInSecurityGroup,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
