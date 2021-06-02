package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSClassicUsage(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check aws_db_security_group",
			source:                `resource "aws_db_security_group" "my-group" {}`,
			mustIncludeResultCode: rules.AWSClassicUsage,
		},
		{
			name:                  "check aws_redshift_security_group",
			source:                `resource "aws_redshift_security_group" "my-group" {}`,
			mustIncludeResultCode: rules.AWSClassicUsage,
		},
		{
			name:                  "check aws_elasticache_security_group",
			source:                `resource "aws_elasticache_security_group" "my-group" {}`,
			mustIncludeResultCode: rules.AWSClassicUsage,
		},
		{
			name:                  "check for false positives",
			source:                `resource "my_resource" "my-resource" {}`,
			mustExcludeResultCode: rules.AWSClassicUsage,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
