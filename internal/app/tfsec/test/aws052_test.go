package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSRDSEncryptionNotEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Encryption not enabled on db instance",
			source: `
resource "aws_db_instance" "my-db-instance" {
	
}
`,
			mustIncludeResultCode: checks.AWSRDSEncryptionNotEnabled,
		},
		{
			name: "Encryption not enabled on db instance",
			source: `
resource "aws_db_instance" "my-db-instance" {
	kms_key_id = ""
}
`,
			mustIncludeResultCode: checks.AWSRDSEncryptionNotEnabled,
		},
		{
			name: "Encryption enabled on db instance",
			source: `
resource "aws_db_instance" "my-db-instance" {
	kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`,
			mustExcludeResultCode: checks.AWSRDSEncryptionNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
