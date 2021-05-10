package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSRedisClusterBackupRetention(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "cluster with no snapshot retention fails check",
			source: `
resource "aws_elasticache_cluster" "bad_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379
}
`,
			mustIncludeResultCode: checks.AWSRedisClusterBackupRetention,
		},
		{
			name: "cluster with snapshot retention set to 0 fails check",
			source: `
resource "aws_elasticache_cluster" "bad_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379

	snapshot_retention_limit = 0
}
`,
			mustIncludeResultCode: checks.AWSRedisClusterBackupRetention,
		},
		{
			name: "Cluster which is memcached but no retention passes check",
			source: `
resource "aws_elasticache_cluster" "good_example" {
	cluster_id           = "cluster-example"
	engine               = "memcached"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 2
	parameter_group_name = "default.memcached1.4"
	port                 = 11211
}
`,
			mustExcludeResultCode: checks.AWSRedisClusterBackupRetention,
		},
		{
			name: "Cluster with small node type passes without snapshot retention passes check",
			source: `
resource "aws_elasticache_cluster" "good_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.t1.micro"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379
}
`,
			mustExcludeResultCode: checks.AWSRedisClusterBackupRetention,
		},
		{
			name: "Cluster with small node type passes without snapshot retention passes check",
			source: `
resource "aws_elasticache_cluster" "good_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379

	snapshot_retention_limit = 5
}
`,
			mustExcludeResultCode: checks.AWSRedisClusterBackupRetention,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
