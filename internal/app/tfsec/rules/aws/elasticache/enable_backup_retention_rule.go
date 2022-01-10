package elasticache

import (
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS088",
		BadExample: []string{`
 resource "aws_elasticache_cluster" "bad_example" {
 	cluster_id           = "cluster-example"
 	engine               = "redis"
 	node_type            = "cache.m4.large"
 	num_cache_nodes      = 1
 	parameter_group_name = "default.redis3.2"
 	engine_version       = "3.2.10"
 	port                 = 6379
 }
 `},
		GoodExample: []string{`
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
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_cluster"},
		Base:           elasticache.CheckEnableBackupRetention,
	})
}
