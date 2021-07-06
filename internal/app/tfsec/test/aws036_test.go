package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedInTransitElasticacheReplicationGroup(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_elasticache_replication_group missing transit_encryption_enabled",
			source: `
resource "aws_elasticache_replication_group" "my-resource" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"
}`,
			mustIncludeResultCode: rules.AWSUnencryptedInTransitElasticacheReplicationGroup,
		},
		{
			name: "check aws_elasticache_replication_group with transit_encryption_enabled",
			source: `
resource "aws_elasticache_replication_group" "my-resource" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = true
}`,
			mustExcludeResultCode: rules.AWSUnencryptedInTransitElasticacheReplicationGroup,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
