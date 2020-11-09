package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSRDSPerformanceInsughtsEncryptionNotEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Performance insights enabled but no kms key provided",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = ""
}
`,
			mustIncludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights disable",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = false

}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights not mentioned",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  
}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights enabled and kms key provided",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights on aws_db_instance enabled but no kms key provided",
			source: `
resource "aws_db_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = ""
}
`,
			mustIncludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		}, {
			name: "Performance insights on aws_db_instance disable",
			source: `
resource "aws_db_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = false

}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights on aws_db_instance not mentioned",
			source: `
resource "aws_db_instance" "foo" {
  
}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
		{
			name: "Performance insights enabled on aws_db_instance and kms key provided",
			source: `
resource "aws_db_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`,
			mustExcludeResultCode: checks.AWSRDSPerformanceInsughtsEncryptionNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
