package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSPublic(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check aws_db_instance when publicly exposed",
			source: `
resource "aws_db_instance" "my-resource" {
	publicly_accessible = true
}`,
			mustIncludeResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_dms_replication_instance when publicly exposed",
			source: `
resource "aws_dms_replication_instance" "my-resource" {
	publicly_accessible = true
}`,
			mustIncludeResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_rds_cluster_instance when publicly exposed",
			source: `
resource "aws_rds_cluster_instance" "my-resource" {
	publicly_accessible = true
}`,
			mustIncludeResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_redshift_cluster when publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = true
}`,
			mustIncludeResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_redshift_cluster when not publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = false
}`,
			mustExcludeResultCode: checks.AWSPubliclyAccessibleResource,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
