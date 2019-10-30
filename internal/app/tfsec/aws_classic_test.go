package tfsec

import (
	"testing"

	"github.com/liamg/tfsec/internal/app/tfsec/checks"
)

func Test_AWSClassicUsage(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		expectedResultCode checks.Code
	}{
		{
			name:               "check aws_db_security_group",
			source:             `resource "aws_db_security_group" "my-group" {}`,
			expectedResultCode: checks.AWSClassicUsage,
		},
		{
			name:               "check aws_redshift_security_group",
			source:             `resource "aws_redshift_security_group" "my-group" {}`,
			expectedResultCode: checks.AWSClassicUsage,
		},
		{
			name:               "check aws_elasticache_security_group",
			source:             `resource "aws_elasticache_security_group" "my-group" {}`,
			expectedResultCode: checks.AWSClassicUsage,
		},
		{
			name:               "check for false positives",
			source:             `resource "my_resource" "my-resource" {}`,
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
