package rds

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSClassicUsage(t *testing.T) {
	expectedCode := "aws-rds-no-classic-resources"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check aws_db_security_group",
			source:                `resource "aws_db_security_group" "my-group" {}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name:                  "check aws_redshift_security_group",
			source:                `resource "aws_redshift_security_group" "my-group" {}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name:                  "check aws_elasticache_security_group",
			source:                `resource "aws_elasticache_security_group" "my-group" {}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name:                  "check for false positives",
			source:                `resource "my_resource" "my-resource" {}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
