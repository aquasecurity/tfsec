package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSRdsClusterEncryptionNotEnabled(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name:                  "check RDS Encryption is disabled",
			source:                `resource "aws_rds_cluster" "foo" {}`,
			mustIncludeResultCode: checks.AWSRdsClusterEncryptionNotEnabled,
		},
		{
			name: "check RDS Cluster Encryption is disabled",
			source: `
resource "aws_rds_cluster" "foo" {
  name                 = "bar"
  kms_key_id = ""
}`,
			mustIncludeResultCode: checks.AWSRdsClusterEncryptionNotEnabled,
		},
		{
			name: "check RDS Cluster Encryption is disabled",
			source: `
resource "aws_rds_cluster" "foo" {
  name                 = "bar"
  kms_key_id = ""
}`,
			mustExcludeResultCode: checks.AWSRdsClusterEncryptionNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
