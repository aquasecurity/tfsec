package rds

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSPublic(t *testing.T) {
	expectedCode := "aws-rds-no-public-db-access"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_db_instance when publicly exposed",
			source: `
 resource "aws_db_instance" "my-resource" {
 	publicly_accessible = true
 }`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check aws_rds_cluster_instance when publicly exposed",
			source: `
resource "aws_rds_cluster" "cluster1" {

}


 resource "aws_rds_cluster_instance" "my-resource" {
	cluster_identifier = aws_rds_cluster.cluster1.id
 	publicly_accessible = true
 }`,
			mustIncludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
