package elasticache

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_cluster"},
		Base:           elasticache.CheckEnableBackupRetention,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			engineAttr := resourceBlock.GetAttribute("engine")
			if engineAttr.IsNotNil() && engineAttr.Equals("redis", block.IgnoreCase) {
				nodeTypeAttr := resourceBlock.GetAttribute("node_type")
				if nodeTypeAttr.IsNotNil() && !nodeTypeAttr.Equals("cache.t1.micro") {
					snapshotRetentionAttr := resourceBlock.GetAttribute("snapshot_retention_limit")
					if snapshotRetentionAttr.IsNil() {
						results.Add("Resource should have snapshot retention specified", resourceBlock)
						return
					}

					if snapshotRetentionAttr.Equals(0) {
						results.Add("Resource has snapshot retention set to 0", snapshotRetentionAttr)
					}
				}
			}

			return results
		},
	})
}
