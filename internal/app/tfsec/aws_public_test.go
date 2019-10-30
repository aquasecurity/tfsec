package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSPublic(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name: "check aws_db_instance when publicly exposed",
			source: `
resource "aws_db_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectedResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_dms_replication_instance when publicly exposed",
			source: `
resource "aws_dms_replication_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectedResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_rds_cluster_instance when publicly exposed",
			source: `
resource "aws_rds_cluster_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectedResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_redshift_cluster when publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = true
}`,
			expectedResultCode: checks.AWSPubliclyAccessibleResource,
		},
		{
			name: "check aws_redshift_cluster when not publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = false
}`,
			expectedResultCode: checks.None,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCodeExists(t, test.expectedResultCode, results)
		})
	}

}
