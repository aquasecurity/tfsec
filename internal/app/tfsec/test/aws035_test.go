package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedAtRestElasticacheReplicationGroup(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_elasticache_replication_group missing at_rest_encryption_enabled",
			source: `
resource "aws_elasticache_replication_group" "my-resource" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"
}`,
			mustIncludeResultCode: rules.AWSUnencryptedAtRestElasticacheReplicationGroup,
		},
		{
			name: "check aws_elasticache_replication_group with at_rest_encryption_enabled",
			source: `
resource "aws_elasticache_replication_group" "my-resource" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        at_rest_encryption_enabled = true
}`,
			mustExcludeResultCode: rules.AWSUnencryptedAtRestElasticacheReplicationGroup,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
