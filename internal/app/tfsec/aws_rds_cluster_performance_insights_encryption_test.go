package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSRdsClusterPerformanceInsightsEncryptionNotEnabled(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleID
		mustExcludeResultCode scanner.RuleID
	}{
		{
			name:                  "check RDS Cluster Performance Insights Encryption is disabled",
			source:                `resource "aws_rds_cluster_instance" "foo" {}`,
			mustIncludeResultCode: checks.AWSRdsClusterPerformanceInsightsEncryptionNotEnabled,
		},
		{
			name: "check RDS Aurora Cluster Performance Insights Encryption is disabled",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = "bar"
  performance_insights_kms_key_id = ""
}`,
			mustIncludeResultCode: checks.AWSRdsClusterPerformanceInsightsEncryptionNotEnabled,
		},
		{
			name: "check RDS Aurora Cluster Performance Insights Encryption is disabled",
			source: `
resource "aws_rds_cluster_instance" "foo" {
  name                 = "bar"
  performance_insights_enabled = "bar"
  performance_insights_kms_key_id = ""
}`,
			mustExcludeResultCode: checks.AWSRdsClusterPerformanceInsightsEncryptionNotEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
