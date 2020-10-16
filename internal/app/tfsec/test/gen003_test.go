package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSSensitiveAttributes(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check sensitive attribute",
			source: `
resource "evil_corp" "virtual_machine" {
	root_password = "secret"
}`,
			mustIncludeResultCode: checks.GenericSensitiveAttributes,
		},
		{
			name: "check non-sensitive local",
			source: `
resource "evil_corp" "virtual_machine" {
	memory = 512
}`,
			mustExcludeResultCode: checks.GenericSensitiveAttributes,
		},
		{
			name: "avoid false positive for aws_efs_file_system",
			source: `
resource "aws_efs_file_system" "myfs" {
	creation_token = "something"
}`,
			mustExcludeResultCode: checks.GenericSensitiveAttributes,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
