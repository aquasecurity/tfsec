package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/scanner"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSClassicUsage(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.CheckCode
		mustExcludeResultCode scanner.CheckCode
	}{
		{
			name:                  "check aws_db_security_group",
			source:                `resource "aws_db_security_group" "my-group" {}`,
			mustIncludeResultCode: checks.AWSClassicUsage,
		},
		{
			name:                  "check aws_redshift_security_group",
			source:                `resource "aws_redshift_security_group" "my-group" {}`,
			mustIncludeResultCode: checks.AWSClassicUsage,
		},
		{
			name:                  "check aws_elasticache_security_group",
			source:                `resource "aws_elasticache_security_group" "my-group" {}`,
			mustIncludeResultCode: checks.AWSClassicUsage,
		},
		{
			name:                  "check for false positives",
			source:                `resource "my_resource" "my-resource" {}`,
			mustExcludeResultCode: checks.AWSClassicUsage,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
